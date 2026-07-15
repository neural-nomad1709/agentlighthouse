"""Gateway HTTP app — fetch proxy + OpenAI/Anthropic reverse proxy (L1).

The data-plane FastAPI app agents talk to. Three ingress modes share one
policy spine:

* ``GET /fetch?url=`` — agent-identity auth, EgressPolicy per redirect hop,
  connect to the **pinned IP** (SNI/Host keep the hostname), size cap.
* ``POST /v1/chat/completions`` (OpenAI-compatible) and ``POST /v1/messages``
  (Anthropic-compatible) — virtual-key auth + daily budget, real provider key
  swapped in from config secrets, SSE passthrough, post-hoc token accounting.

Every decision is receipted. The control-plane app (``al_core.app``) stays
separate — this app runs where agents can reach it; that one must not.
"""

from __future__ import annotations

import json
import logging
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from ..detect import ScanContext
from ..detect.budget import domain_of
from ..mcp.session import McpSession
from ..runtime import Runtime
from .content import decode_body, receipt_extras, scan_sse_stream
from .decision import BlockReason, Decision, finding
from .forward import ForwardProxy
from .policy import EgressPolicy
from .ssrf import check_url as check_url_shape

log = logging.getLogger("al.gateway.web")

ANONYMOUS = "anonymous"
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
_USAGE_SCAN_CAP = 2 * 1024 * 1024  # SSE bytes retained for usage parsing


def _ms(t0: float) -> int:
    """Elapsed whole milliseconds since ``t0`` (monotonic) — receipt latency."""
    return max(0, int((time.monotonic() - t0) * 1000))


def _block_response(decision: Decision, status: int) -> JSONResponse:
    return JSONResponse(
        {"error": "blocked", "block_reason": decision.block_reason},
        status_code=status,
        headers={"X-AL-Block-Reason": decision.block_reason or ""},
    )


def _pinned_url(original: str, ip: str, port: int) -> tuple[str, str]:
    """(url-with-ip, host-header) so the connection cannot re-resolve DNS."""
    parts = urlsplit(original)
    host = parts.hostname or ""
    netloc_ip = f"[{ip}]" if ":" in ip else ip
    pinned = urlunsplit(
        (parts.scheme, f"{netloc_ip}:{port}", parts.path or "/", parts.query, "")
    )
    default_port = 443 if parts.scheme == "https" else 80
    host_header = host if port == default_port else f"{host}:{port}"
    return pinned, host_header


def _openai_usage(payload: dict[str, Any]) -> int:
    usage = payload.get("usage") or {}
    total = usage.get("total_tokens")
    if isinstance(total, int):
        return total
    p, c = usage.get("prompt_tokens"), usage.get("completion_tokens")
    return (p or 0) + (c or 0) if isinstance(p, int) or isinstance(c, int) else 0


def _anthropic_usage(payload: dict[str, Any]) -> int:
    usage = payload.get("usage") or {}
    i, o = usage.get("input_tokens"), usage.get("output_tokens")
    return (i or 0) + (o or 0) if isinstance(i, int) or isinstance(o, int) else 0


def _request_text(body: dict[str, Any]) -> str:
    """Flatten a chat request's message text for outbound DLP scanning.

    Covers OpenAI (``messages[].content`` str or content-part list) and
    Anthropic (``system`` + ``messages[].content`` blocks). System prompt and
    all roles are included — a secret leaks the same whichever field carries it.
    """
    parts: list[str] = []
    system = body.get("system")
    if isinstance(system, str):
        parts.append(system)
    elif isinstance(system, list):
        parts.extend(b.get("text", "") for b in system if isinstance(b, dict))
    for msg in body.get("messages", []) or []:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    parts.append(block["text"])
    return "\n".join(p for p in parts if p)


def _redact_request(body: dict[str, Any], gate) -> dict[str, Any]:
    """Return a copy of a chat request with each string message field passed
    through the gate's redaction (typed placeholders substituted in place).

    Redacting per-field keeps message structure intact and each placeholder
    local to the field it came from — no fragile offset-mapping across a
    flattened prompt."""
    def redact(text: str) -> str:
        r = gate.scan_text(text)
        return r.text if r.verdict == "strip" else text

    out = dict(body)
    system = body.get("system")
    if isinstance(system, str):
        out["system"] = redact(system)
    elif isinstance(system, list):
        out["system"] = [
            {**b, "text": redact(b["text"])} if isinstance(b, dict) and isinstance(b.get("text"), str) else b
            for b in system
        ]
    messages = body.get("messages")
    if isinstance(messages, list):
        new_msgs = []
        for msg in messages:
            if not isinstance(msg, dict):
                new_msgs.append(msg)
                continue
            content = msg.get("content")
            if isinstance(content, str):
                new_msgs.append({**msg, "content": redact(content)})
            elif isinstance(content, list):
                new_msgs.append({**msg, "content": [
                    {**b, "text": redact(b["text"])}
                    if isinstance(b, dict) and isinstance(b.get("text"), str) else b
                    for b in content
                ]})
            else:
                new_msgs.append(msg)
        out["messages"] = new_msgs
    return out


def _response_text(provider: str, payload: dict[str, Any]) -> str:
    """Assistant output text from a non-streaming completion (for scanning)."""
    out: list[str] = []
    if provider == "openai":
        for choice in payload.get("choices", []) or []:
            msg = choice.get("message") or {}
            if isinstance(msg.get("content"), str):
                out.append(msg["content"])
    else:  # anthropic
        for block in payload.get("content", []) or []:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                out.append(block["text"])
    return "\n".join(out)


def _sse_usage(provider: str, body_text: str) -> int:
    """Best-effort token count from an SSE stream (0 when absent).

    OpenAI sends usage only in the final chunk (and only when the client asked
    via ``stream_options``); Anthropic splits it across ``message_start``
    (input) and the last ``message_delta`` (output). Missing usage costs the
    key nothing beyond the request count — acceptable for Phase 1.
    """
    tokens = 0
    anthropic_in = anthropic_out = 0
    for line in body_text.splitlines():
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if not data or data == "[DONE]":
            continue
        try:
            payload = json.loads(data)
        except json.JSONDecodeError:
            continue
        if provider == "openai":
            got = _openai_usage(payload)
            if got:
                tokens = got  # final chunk carries the authoritative total
        else:
            usage = payload.get("usage") or (payload.get("message") or {}).get("usage") or {}
            if isinstance(usage.get("input_tokens"), int):
                anthropic_in = usage["input_tokens"]
            if isinstance(usage.get("output_tokens"), int):
                anthropic_out = usage["output_tokens"]  # cumulative; keep last
    if provider == "anthropic":
        tokens = anthropic_in + anthropic_out
    return tokens


def create_gateway_app(
    runtime: Runtime,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    resolve: Any = None,
    forward_listen: str | None = None,
) -> FastAPI:
    """Build the data-plane app. ``transport``/``resolve`` are test seams.

    When ``forward_listen`` ("host:port") is given, the CONNECT forward proxy
    is started on the app's lifespan and exposed as ``app.state.forward_proxy``.
    """

    policy_cache: dict[str, EgressPolicy] = {}

    def _policy() -> EgressPolicy:
        """EgressPolicy for the *current* config; rebuilt on hot-reload."""
        s = runtime.settings
        key = runtime.config_hash
        if key not in policy_cache:
            policy_cache.clear()  # drop stale policies (pins die with them)
            policy_cache[key] = EgressPolicy(
                allow_hosts=s.gateway.allow_hosts,
                allow_ports=s.gateway.allow_ports,
                url_max_len=s.scanner.url_max_len,
                block_private=s.scanner.ssrf.block_private,
                rebind_protection=s.scanner.ssrf.dns_rebind_protection,
                pin_ttl_s=s.gateway.pin_ttl_s,
                resolve=resolve,
            )
        return policy_cache[key]

    client = httpx.AsyncClient(
        transport=transport,
        follow_redirects=False,  # redirects re-enter policy per hop
        timeout=httpx.Timeout(runtime.settings.gateway.request_timeout_s),
    )

    @asynccontextmanager
    async def lifespan(app_: FastAPI) -> AsyncIterator[None]:
        forward: ForwardProxy | None = None
        if forward_listen is not None:
            fwd_host, _, fwd_port = forward_listen.rpartition(":")
            forward = ForwardProxy(
                policy=_policy(),
                registry=runtime.registry,
                recorder=runtime.record,
                require_identity=runtime.settings.gateway.require_identity,
                connect_timeout_s=runtime.settings.gateway.request_timeout_s,
                killswitch=runtime.killswitch.engaged,
            )
            await forward.start(fwd_host or "127.0.0.1", int(fwd_port))
            app_.state.forward_proxy = forward
            log.info("forward (CONNECT) proxy listening on %s:%s", fwd_host, forward.bound_port)
        yield
        if forward is not None:
            await forward.stop()
        await client.aclose()

    app = FastAPI(title="AgentLighthouse Gateway", version="0.1.0", lifespan=lifespan)
    app.state.runtime = runtime

    @app.middleware("http")
    async def killswitch_deny_all(request: Request, call_next):
        """L6 kill switch: engaged -> every data-plane request is denied.

        /healthz stays answerable (it reports the deny-all state; operators
        need it during an incident). Per-request denials are NOT individually
        receipted — the engagement itself is the signed standing decision; a
        retry-looping agent must not be able to flood the evidence ledger."""
        if request.url.path != "/healthz" and runtime.killswitch.engaged():
            return _block_response(
                Decision.block(BlockReason.KILLSWITCH_ENGAGED), 503)
        return await call_next(request)

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        # Same payload as the control-plane app; the gateway process owns the
        # ledger, so health must be answerable here without a second Runtime.
        payload = runtime.healthz()
        return JSONResponse(payload, status_code=200 if payload["status"] == "healthy" else 503)

    # -- fetch proxy ---------------------------------------------------------

    @app.get("/fetch")
    async def fetch(request: Request, url: str) -> Response:
        t0 = time.monotonic()
        s = runtime.settings
        ident = runtime.registry.authenticate(
            request.headers.get("x-al-identity"),
            _bearer(request.headers.get("authorization")),
        )
        actor = ident.spiffe_id if ident else ANONYMOUS
        if ident is None and s.gateway.require_identity:
            decision = Decision.block(
                BlockReason.NO_IDENTITY,
                [finding("egress_policy", "identity.missing", "high", owasp="ASI03")],
            )
            runtime.record(
                actor=actor, action="fetch", target=url,
                verdict="block", block_reason=decision.block_reason,
                findings=decision.findings, latency_ms=_ms(t0),
            )
            return _block_response(decision, 401)

        # Rate limit: one slot per fetch, keyed on the requested destination
        # (denial-of-wallet / loop-storm guard). Checked before any egress.
        rl_domain = domain_of(url)
        rl_ok, rl_reason = runtime.rate_budget.try_request(rl_domain)
        if not rl_ok:
            decision = Decision.block(
                rl_reason,
                [finding("rate_budget", "rate.per_domain_rps", "medium", owasp="ASI08")],
            )
            runtime.record(
                actor=actor, action="fetch", target=url,
                verdict="block", block_reason=decision.block_reason,
                findings=decision.findings, latency_ms=_ms(t0),
            )
            return _block_response(decision, 429)

        current = url
        for _hop in range(s.gateway.max_redirects + 1):
            shape = check_url_shape(current, url_max_len=s.scanner.url_max_len)
            if isinstance(shape, Decision):
                decision = shape
            else:
                host, port = shape
                decision = _policy().check_connect(host, port)
            if not decision.allowed:
                runtime.record(
                    actor=actor, action="fetch", target=current,
                    verdict="block", block_reason=decision.block_reason,
                    findings=decision.findings, latency_ms=_ms(t0),
                )
                return _block_response(decision, 403)

            assert decision.pin is not None
            pinned, host_header = _pinned_url(current, decision.pin.ip, port)
            try:
                upstream = await client.get(
                    pinned,
                    headers={"Host": host_header, "Accept": "*/*",
                             "User-Agent": "agentlighthouse-fetch"},
                    extensions={"sni_hostname": host},
                )
            except httpx.HTTPError as exc:
                log.warning("fetch upstream error for %s: %s", current, exc)
                return JSONResponse({"error": "upstream_unreachable"}, status_code=502)

            if upstream.status_code in _REDIRECT_CODES and "location" in upstream.headers:
                current = urljoin(current, upstream.headers["location"])
                continue

            body = upstream.content
            if len(body) > s.gateway.fetch_max_bytes:
                decision = Decision.block(
                    BlockReason.SIZE_EXCEEDED,
                    [finding("data_budget", "fetch.size_exceeded", "medium", owasp="ASI08")],
                )
                runtime.record(
                    actor=actor, action="fetch", target=current,
                    verdict="block", block_reason=decision.block_reason,
                    findings=decision.findings, latency_ms=_ms(t0),
                )
                return _block_response(decision, 502)

            # Per-domain daily data budget (denial-of-wallet across many calls).
            budget_ok, budget_reason = runtime.rate_budget.try_data(rl_domain, len(body))
            if not budget_ok:
                decision = Decision.block(
                    budget_reason,
                    [finding("data_budget", "fetch.per_domain_bytes", "medium", owasp="ASI08")],
                )
                runtime.record(
                    actor=actor, action="fetch", target=current,
                    verdict="block", block_reason=decision.block_reason,
                    findings=decision.findings, latency_ms=_ms(t0),
                )
                return _block_response(decision, 429)

            # L2/L3 content gate on the fetched body (injection/secrets/PII/
            # SSRF/entropy). Fetched content is untrusted inbound data — the
            # classic indirect-injection carrier.
            content_type = upstream.headers.get("content-type", "application/octet-stream")
            scan_text = decode_body(body, content_type)
            if scan_text is not None:
                result = await runtime.content_gate.scan(
                    scan_text,
                    ScanContext(actor=actor, direction="inbound", target=current,
                                content_type=content_type),
                )
                if result.blocked:
                    runtime.record(
                        actor=actor, action="fetch", target=current, verdict="block",
                        block_reason=result.block_reason, latency_ms=_ms(t0),
                        **receipt_extras(result),
                    )
                    return _block_response(
                        Decision.block(result.block_reason, result.findings), 403
                    )
                if result.verdict in ("strip", "warn"):
                    runtime.record(
                        actor=actor, action="fetch", target=current,
                        verdict=result.verdict, latency_ms=_ms(t0),
                        **receipt_extras(result),
                    )
                    return Response(
                        content=result.text.encode("utf-8"),
                        status_code=upstream.status_code,
                        media_type=content_type,
                    )

            runtime.record(actor=actor, action="fetch", target=current,
                           verdict="allow", latency_ms=_ms(t0))
            return Response(
                content=body,
                status_code=upstream.status_code,
                media_type=content_type,
            )

        decision = Decision.block(
            BlockReason.TOO_MANY_REDIRECTS,
            [finding("egress_policy", "fetch.redirect_limit", "medium", owasp="ASI02")],
        )
        runtime.record(
            actor=actor, action="fetch", target=current,
            verdict="block", block_reason=decision.block_reason,
            findings=decision.findings, latency_ms=_ms(t0),
        )
        return _block_response(decision, 403)

    # -- MCP reverse proxy (Streamable-HTTP ingress) ----------------------------

    mcp_sessions: dict[str, "McpSession"] = {}

    @app.post("/mcp")
    async def mcp_reverse(request: Request) -> Response:
        """HTTP-reverse MCP transport: the agent's MCP client points here; each
        POSTed JSON-RPC message runs through McpSession (pin/poison on
        tools/list, ActionGate on tools/call, result scan on responses) before
        touching the operator-configured upstream. JSON replies only — an SSE
        upstream response is a later increment."""
        s = runtime.settings
        ident = runtime.registry.authenticate(
            request.headers.get("x-al-identity"),
            _bearer(request.headers.get("authorization")),
        )
        actor = ident.spiffe_id if ident else ANONYMOUS
        if ident is None and s.gateway.require_identity:
            decision = Decision.block(
                BlockReason.NO_IDENTITY,
                [finding("egress_policy", "identity.missing", "high", owasp="ASI03")],
            )
            runtime.record(actor=actor, action="mcp_tool_call", target="mcp:ingress",
                           verdict="block", block_reason=decision.block_reason,
                           findings=decision.findings, session=f"mcp:{actor}")
            return _block_response(decision, 401)
        if not s.gateway.mcp_upstream_url:
            return _block_response(
                Decision.block(BlockReason.UPSTREAM_NOT_CONFIGURED), 502)

        try:
            msg = await request.json()
        except Exception:  # noqa: BLE001 — malformed body
            return JSONResponse({"error": "invalid_json"}, status_code=400)
        if not isinstance(msg, dict):
            return JSONResponse({"error": "invalid_message"}, status_code=400)

        session = mcp_sessions.get(actor)
        if session is None:
            session = McpSession(runtime.mcp_mediator, actor=actor,
                                 session_id=f"mcp:{actor}")
            mcp_sessions[actor] = session

        out = session.filter_request(msg)
        if out.reply is not None:
            return JSONResponse(out.reply)
        if out.forward is None:
            return Response(status_code=202)
        try:
            upstream = await client.post(
                s.gateway.mcp_upstream_url, json=out.forward,
                headers={"Accept": "application/json",
                         "Content-Type": "application/json"})
        except httpx.HTTPError as exc:
            log.warning("mcp upstream error: %s", exc)
            return JSONResponse({"error": "upstream_unreachable"}, status_code=502)
        if upstream.status_code == 202 or not upstream.content:
            return Response(status_code=202)
        try:
            payload = upstream.json()
        except ValueError:
            return JSONResponse({"error": "upstream_invalid_json"}, status_code=502)
        if isinstance(payload, dict):
            return JSONResponse(session.filter_response(payload))
        return JSONResponse(payload)

    # -- reverse proxy (OpenAI + Anthropic compatible) -------------------------

    @app.post("/v1/chat/completions")
    async def openai_chat(request: Request) -> Response:
        return await _llm_call(request, provider="openai", path="/v1/chat/completions")

    @app.post("/v1/messages")
    async def anthropic_messages(request: Request) -> Response:
        return await _llm_call(request, provider="anthropic", path="/v1/messages")

    async def _llm_call(request: Request, *, provider: str, path: str) -> Response:
        t0 = time.monotonic()
        s = runtime.settings
        token = _bearer(request.headers.get("authorization")) or request.headers.get("x-api-key")
        vkey = runtime.vkeys.authenticate(token)
        if vkey is None:
            decision = Decision.block(
                BlockReason.INVALID_VIRTUAL_KEY,
                [finding("egress_policy", "vkey.invalid", "high", owasp="ASI03")],
            )
            runtime.record(
                actor=ANONYMOUS, action="llm_call", target=f"{provider}:{path}",
                verdict="block", block_reason=decision.block_reason,
                findings=decision.findings, latency_ms=_ms(t0),
            )
            return _block_response(decision, 401)

        try:
            body = await request.json()
        except json.JSONDecodeError:
            return JSONResponse({"error": "invalid_json"}, status_code=400)
        model = str(body.get("model", "unknown"))
        target = f"{provider}:{model}"

        # Outbound DLP: scan the prompt before it leaves for the provider. A
        # secret / seed phrase / injection heading upstream is a leak (or a
        # prompt-injection carrier) — block it, and do not consume budget or
        # touch the real key.
        outbound_extras: dict[str, Any] = {}
        req_text = _request_text(body)
        if req_text:
            dlp = await runtime.content_gate.scan(
                req_text,
                ScanContext(actor=vkey.actor, direction="outbound", target=target,
                            content_type="application/json"),
            )
            if dlp.blocked:
                runtime.record(
                    actor=vkey.actor, action="llm_call", target=target, verdict="block",
                    block_reason=dlp.block_reason, latency_ms=_ms(t0),
                    **receipt_extras(dlp),
                )
                return _block_response(
                    Decision.block(dlp.block_reason, dlp.findings), 403
                )
            if dlp.verdict in ("strip", "warn"):
                outbound_extras = receipt_extras(dlp)
            if dlp.verdict == "strip":
                # Redact secrets/PII out of the prompt rather than fail the call.
                body = _redact_request(body, runtime.content_gate)

        upstream_cfg = s.gateway.upstream
        if provider == "openai":
            base, real_key = upstream_cfg.openai_base_url, upstream_cfg.openai_api_key
        else:
            base, real_key = upstream_cfg.anthropic_base_url, upstream_cfg.anthropic_api_key
        if real_key is None:
            decision = Decision.block(BlockReason.UPSTREAM_NOT_CONFIGURED)
            runtime.record(
                actor=vkey.actor, action="llm_call", target=target,
                verdict="block", block_reason=decision.block_reason,
                latency_ms=_ms(t0),
            )
            return _block_response(decision, 502)

        # Budget is consumed last, only for requests that will actually go out.
        if not runtime.budget.try_consume(vkey, requests=1):
            decision = Decision.block(
                BlockReason.BUDGET_EXCEEDED,
                [finding("rate_budget", "budget.llm_daily", "medium", owasp="ASI08")],
            )
            runtime.record(
                actor=vkey.actor, action="llm_call", target=target,
                verdict="block", block_reason=decision.block_reason,
                findings=decision.findings, latency_ms=_ms(t0),
            )
            return _block_response(decision, 429)

        # The agent's virtual key never leaves this process; the real key is
        # injected here and never appears in any receipt or log.
        headers = {"Content-Type": "application/json"}
        if provider == "openai":
            headers["Authorization"] = f"Bearer {real_key.get_secret_value()}"
        else:
            headers["x-api-key"] = real_key.get_secret_value()
            headers["anthropic-version"] = request.headers.get(
                "anthropic-version", "2023-06-01"
            )

        # The send is authorized; redaction/warn findings from the outbound
        # scan ride this receipt (counts only, never plaintext).
        runtime.record(actor=vkey.actor, action="llm_call", target=target,
                       verdict="strip" if outbound_extras.get("redaction") else "allow",
                       latency_ms=_ms(t0), **outbound_extras)

        resp_ctx = ScanContext(actor=vkey.actor, direction="inbound", target=target,
                               content_type="text/event-stream")
        upstream_url = base.rstrip("/") + path
        if bool(body.get("stream")):
            req = client.build_request("POST", upstream_url, json=body, headers=headers)
            try:
                upstream = await client.send(req, stream=True)
            except httpx.HTTPError as exc:
                log.warning("llm upstream error for %s: %s", target, exc)
                return JSONResponse({"error": "upstream_unreachable"}, status_code=502)

            async def relay() -> AsyncIterator[bytes]:
                retained = bytearray()

                async def lines() -> AsyncIterator[bytes]:
                    buf = bytearray()
                    async for chunk in upstream.aiter_raw():
                        if len(retained) < _USAGE_SCAN_CAP:
                            retained.extend(chunk)
                        buf.extend(chunk)
                        while b"\n" in buf:
                            line, _, rest = buf.partition(b"\n")
                            buf = bytearray(rest)
                            yield bytes(line) + b"\n"
                    if buf:
                        yield bytes(buf)

                result_holder: dict[str, Any] = {}

                def on_complete(result, severed, assistant_text) -> None:
                    result_holder["result"] = result
                    result_holder["severed"] = severed

                try:
                    async for out in scan_sse_stream(
                        lines(), runtime.content_gate, resp_ctx, on_complete=on_complete
                    ):
                        yield out
                finally:
                    await upstream.aclose()
                    tokens = _sse_usage(provider, retained.decode("utf-8", errors="ignore"))
                    if tokens:
                        runtime.budget.add_usage(vkey, tokens=tokens)
                    result = result_holder.get("result")
                    if result is not None and result.blocked:
                        runtime.record(
                            actor=vkey.actor, action="llm_call",
                            target=f"{target}:response", verdict="block",
                            block_reason=result.block_reason, latency_ms=_ms(t0),
                            **receipt_extras(result),
                        )

            return StreamingResponse(
                relay(),
                status_code=upstream.status_code,
                media_type=upstream.headers.get("content-type", "text/event-stream"),
            )

        try:
            upstream = await client.post(upstream_url, json=body, headers=headers)
        except httpx.HTTPError as exc:
            log.warning("llm upstream error for %s: %s", target, exc)
            return JSONResponse({"error": "upstream_unreachable"}, status_code=502)

        tokens = 0
        payload = None
        try:
            payload = upstream.json()
            tokens = _openai_usage(payload) if provider == "openai" else _anthropic_usage(payload)
        except (json.JSONDecodeError, ValueError):
            pass
        if tokens:
            runtime.budget.add_usage(vkey, tokens=tokens)

        # Inbound content scan of the assistant's reply — an LLM can be steered
        # into emitting injection/secrets aimed at downstream tools.
        if payload is not None and 200 <= upstream.status_code < 300:
            reply = _response_text(provider, payload)
            if reply:
                result = await runtime.content_gate.scan(reply, resp_ctx)
                if result.blocked:
                    runtime.record(
                        actor=vkey.actor, action="llm_call",
                        target=f"{target}:response", verdict="block",
                        block_reason=result.block_reason, latency_ms=_ms(t0),
                        **receipt_extras(result),
                    )
                    return _block_response(
                        Decision.block(result.block_reason, result.findings), 403
                    )
                if result.verdict in ("strip", "warn"):
                    runtime.record(
                        actor=vkey.actor, action="llm_call",
                        target=f"{target}:response", verdict=result.verdict,
                        latency_ms=_ms(t0), **receipt_extras(result),
                    )
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "application/json"),
        )

    return app


def _bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token else None


__all__ = ["create_gateway_app"]
