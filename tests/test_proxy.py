"""L1 proxy modes (proxy_test — Phase 1 acceptance).

Fetch proxy: identity required, per-hop policy, pinned-IP connection, size cap.
Reverse proxy: per-user virtual key + budget enforced, real key swap, SSE
passthrough, post-hoc token accounting. Forward proxy: CONNECT through the
same policy spine, tunnel to the pinned IP only.
"""

from __future__ import annotations

import asyncio
import base64
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from al_core.gateway.decision import BlockReason
from al_core.gateway.forward import ForwardProxy
from al_core.gateway.policy import EgressPolicy
from al_core.gateway.web import create_gateway_app
from al_core.identity import IdentityRegistry
from al_core.runtime import Runtime

PUBLIC_IP = "93.184.216.34"


def _runtime(tmp_path, yaml_text: str) -> Runtime:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(yaml_text, encoding="utf-8")
    return Runtime(cfg, data_dir=tmp_path / "data")


def _last_receipt(runtime: Runtime) -> dict:
    return runtime.ledger.db.recent(limit=1)[0]


def _agent_headers(runtime: Runtime) -> dict[str, str]:
    creds = runtime.registry.issue("acme", "bot")
    return {
        "X-AL-Identity": creds.identity.spiffe_id,
        "Authorization": f"Bearer {creds.token}",
    }


# -- fetch proxy ----------------------------------------------------------------

FETCH_CFG = """
mode: balanced
gateway:
  allow_hosts: ["api.example.com", "*.trusted.com"]
  allow_ports: [443]
  max_redirects: 2
  fetch_max_bytes: 1024
"""


@pytest.fixture
def fetch_app(tmp_path):
    runtime = _runtime(tmp_path, FETCH_CFG)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        path = request.url.path
        if path == "/redirect-private":
            return httpx.Response(302, headers={"location": "https://internal.example/x"})
        if path == "/redirect-loop":
            return httpx.Response(302, headers={"location": "https://api.example.com/redirect-loop"})
        if path == "/big":
            return httpx.Response(200, content=b"x" * 2048)
        return httpx.Response(200, content=b"hello world", headers={"content-type": "text/plain"})

    app = create_gateway_app(
        runtime,
        transport=httpx.MockTransport(handler),
        resolve=lambda host: [PUBLIC_IP],
    )
    with TestClient(app) as client:
        yield client, runtime, seen
    runtime.close()


def test_fetch_without_identity_denied(fetch_app):
    client, runtime, _ = fetch_app
    r = client.get("/fetch", params={"url": "https://api.example.com/x"})
    assert r.status_code == 401
    assert r.headers["x-al-block-reason"] == BlockReason.NO_IDENTITY
    receipt = _last_receipt(runtime)
    assert receipt["action"] == "fetch" and receipt["block_reason"] == BlockReason.NO_IDENTITY


def test_fetch_allowed_host_pins_ip(fetch_app):
    client, runtime, seen = fetch_app
    r = client.get(
        "/fetch", params={"url": "https://api.example.com/data"},
        headers=_agent_headers(runtime),
    )
    assert r.status_code == 200 and r.content == b"hello world"
    # The connection went to the pinned IP; the hostname rode in the Host header.
    assert seen[-1].url.host == PUBLIC_IP
    assert seen[-1].headers["host"] == "api.example.com"
    receipt = _last_receipt(runtime)
    assert receipt["verdict"] == "allow" and receipt["actor"].startswith("spiffe://acme/")


def test_fetch_unlisted_host_blocked(fetch_app):
    client, runtime, seen = fetch_app
    r = client.get(
        "/fetch", params={"url": "https://evil.com/x"}, headers=_agent_headers(runtime)
    )
    assert r.status_code == 403
    assert r.headers["x-al-block-reason"] == BlockReason.HOST_NOT_ALLOWED
    assert not seen  # blocked before any network activity


def test_fetch_metadata_ip_blocked(fetch_app):
    client, runtime, seen = fetch_app
    r = client.get(
        "/fetch",
        params={"url": "https://169.254.169.254/latest/meta-data"},
        headers=_agent_headers(runtime),
    )
    assert r.status_code == 403
    assert r.headers["x-al-block-reason"] == BlockReason.HOST_NOT_ALLOWED
    assert not seen


def test_fetch_redirect_to_unlisted_host_blocked(fetch_app):
    client, runtime, seen = fetch_app
    r = client.get(
        "/fetch",
        params={"url": "https://api.example.com/redirect-private"},
        headers=_agent_headers(runtime),
    )
    assert r.status_code == 403  # hop 2 re-enters policy and is denied
    assert r.headers["x-al-block-reason"] == BlockReason.HOST_NOT_ALLOWED
    assert len(seen) == 1


def test_fetch_redirect_limit(fetch_app):
    client, runtime, _ = fetch_app
    r = client.get(
        "/fetch",
        params={"url": "https://api.example.com/redirect-loop"},
        headers=_agent_headers(runtime),
    )
    assert r.status_code == 403
    assert r.headers["x-al-block-reason"] == BlockReason.TOO_MANY_REDIRECTS


def test_fetch_size_cap(fetch_app):
    client, runtime, _ = fetch_app
    r = client.get(
        "/fetch", params={"url": "https://api.example.com/big"},
        headers=_agent_headers(runtime),
    )
    assert r.status_code == 502
    assert r.headers["x-al-block-reason"] == BlockReason.SIZE_EXCEEDED
    assert _last_receipt(runtime)["verdict"] == "block"


def test_fetch_bad_scheme_blocked(fetch_app):
    client, runtime, _ = fetch_app
    r = client.get(
        "/fetch", params={"url": "file:///etc/passwd"}, headers=_agent_headers(runtime)
    )
    assert r.status_code == 403
    assert r.headers["x-al-block-reason"] == BlockReason.SCHEME_NOT_ALLOWED


# -- reverse proxy ---------------------------------------------------------------

OPENAI_SSE = (
    b'data: {"choices":[{"delta":{"content":"Hi"}}]}\n\n'
    b'data: {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}\n\n'
    b"data: [DONE]\n\n"
)

ANTHROPIC_SSE = (
    b'event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":25,"output_tokens":1}}}\n\n'
    b'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":40}}\n\n'
    b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
)


class _SSEStream(httpx.AsyncByteStream):
    """Async stream wrapper — a plain ``content=`` mock is born pre-consumed."""

    def __init__(self, data: bytes, chunk: int = 64) -> None:
        self._chunks = [data[i : i + chunk] for i in range(0, len(data), chunk)]

    async def __aiter__(self):
        for c in self._chunks:
            yield c


@pytest.fixture
def llm_app(tmp_path, monkeypatch):
    monkeypatch.setenv("AL_GATEWAY__UPSTREAM__OPENAI_API_KEY", "sk-real-openai")
    monkeypatch.setenv("AL_GATEWAY__UPSTREAM__ANTHROPIC_API_KEY", "sk-ant-real")
    runtime = _runtime(tmp_path, "mode: balanced\n")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = json.loads(request.content)
        if bool(body.get("stream")):
            data = OPENAI_SSE if request.url.path.endswith("completions") else ANTHROPIC_SSE
            return httpx.Response(
                200, stream=_SSEStream(data), headers={"content-type": "text/event-stream"}
            )
        if request.url.path.endswith("completions"):
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": "hi"}}],
                      "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10}},
            )
        return httpx.Response(
            200,
            json={"content": [{"type": "text", "text": "hi"}],
                  "usage": {"input_tokens": 12, "output_tokens": 8}},
        )

    app = create_gateway_app(runtime, transport=httpx.MockTransport(handler))
    with TestClient(app) as client:
        yield client, runtime, seen
    runtime.close()


def test_llm_invalid_virtual_key_denied(llm_app):
    client, runtime, seen = llm_app
    r = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4o", "messages": []},
        headers={"Authorization": "Bearer alk_bogus"},
    )
    assert r.status_code == 401
    assert r.headers["x-al-block-reason"] == BlockReason.INVALID_VIRTUAL_KEY
    assert not seen  # never reached upstream
    assert _last_receipt(runtime)["actor"] == "anonymous"


def test_llm_missing_key_denied(llm_app):
    client, _, _ = llm_app
    r = client.post("/v1/chat/completions", json={"model": "gpt-4o"})
    assert r.status_code == 401


def test_openai_call_swaps_real_key_and_counts_usage(llm_app):
    client, runtime, seen = llm_app
    vk, token = runtime.vkeys.issue("alice", max_tokens_per_day=1000)
    r = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200 and r.json()["usage"]["total_tokens"] == 10
    # Virtual key never left; the real provider key was swapped in.
    assert seen[-1].headers["authorization"] == "Bearer sk-real-openai"
    assert token not in str(seen[-1].headers)
    assert runtime.budget.usage(vk) == (1, 10)
    receipt = _last_receipt(runtime)
    assert receipt["actor"] == "user:alice" and receipt["target"] == "openai:gpt-4o"
    assert receipt["verdict"] == "allow" and receipt["action"] == "llm_call"


def test_anthropic_call_uses_x_api_key(llm_app):
    client, runtime, seen = llm_app
    vk, token = runtime.vkeys.issue("bob")
    r = client.post(
        "/v1/messages",
        json={"model": "claude-sonnet-5", "max_tokens": 100, "messages": []},
        headers={"x-api-key": token},
    )
    assert r.status_code == 200
    assert seen[-1].headers["x-api-key"] == "sk-ant-real"
    assert seen[-1].headers["anthropic-version"] == "2023-06-01"
    assert runtime.budget.usage(vk) == (1, 20)  # 12 in + 8 out


def test_request_budget_exceeded_denied(llm_app):
    client, runtime, _ = llm_app
    _, token = runtime.vkeys.issue("cheap", max_requests_per_day=1)
    headers = {"Authorization": f"Bearer {token}"}
    assert client.post("/v1/chat/completions", json={"model": "m"}, headers=headers).status_code == 200
    r = client.post("/v1/chat/completions", json={"model": "m"}, headers=headers)
    assert r.status_code == 429
    assert r.headers["x-al-block-reason"] == BlockReason.BUDGET_EXCEEDED
    assert _last_receipt(runtime)["block_reason"] == BlockReason.BUDGET_EXCEEDED


def test_token_budget_blocks_next_request(llm_app):
    client, runtime, _ = llm_app
    _, token = runtime.vkeys.issue("small", max_tokens_per_day=5)
    headers = {"Authorization": f"Bearer {token}"}
    # First call succeeds (pre-flight sees 0 tokens); usage lands it at 10 > 5.
    assert client.post("/v1/chat/completions", json={"model": "m"}, headers=headers).status_code == 200
    r = client.post("/v1/chat/completions", json={"model": "m"}, headers=headers)
    assert r.status_code == 429


def test_openai_sse_passthrough_and_usage(llm_app):
    client, runtime, _ = llm_app
    vk, token = runtime.vkeys.issue("streamer")
    r = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4o", "stream": True},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    assert b"data: [DONE]" in r.content  # stream arrived intact
    assert runtime.budget.usage(vk) == (1, 15)  # usage parsed from final SSE chunk


def test_anthropic_sse_passthrough_and_usage(llm_app):
    client, runtime, _ = llm_app
    vk, token = runtime.vkeys.issue("streamer2")
    r = client.post(
        "/v1/messages",
        json={"model": "claude-sonnet-5", "stream": True, "max_tokens": 50},
        headers={"x-api-key": token},
    )
    assert r.status_code == 200
    assert b"message_stop" in r.content
    assert runtime.budget.usage(vk) == (1, 65)  # 25 in + 40 out (last delta wins)


def test_upstream_not_configured_denied(tmp_path):
    runtime = _runtime(tmp_path, "mode: balanced\n")  # no provider keys in env
    app = create_gateway_app(runtime, transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    with TestClient(app) as client:
        _, token = runtime.vkeys.issue("alice")
        r = client.post(
            "/v1/chat/completions", json={"model": "m"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 502
    assert r.headers["x-al-block-reason"] == BlockReason.UPSTREAM_NOT_CONFIGURED
    runtime.close()


def test_real_provider_key_never_in_ledger(llm_app, tmp_path):
    client, runtime, _ = llm_app
    _, token = runtime.vkeys.issue("alice")
    client.post(
        "/v1/chat/completions", json={"model": "m"},
        headers={"Authorization": f"Bearer {token}"},
    )
    ledger_text = (tmp_path / "data" / "ledger.jsonl").read_text(encoding="utf-8")
    assert "sk-real-openai" not in ledger_text
    assert token not in ledger_text


# -- forward (CONNECT) proxy -------------------------------------------------------

def _proxy_auth(sid: str, token: str) -> bytes:
    blob = base64.b64encode(f"{sid}:{token}".encode()).decode()
    return f"Proxy-Authorization: Basic {blob}\r\n".encode()


async def _echo_server() -> tuple[asyncio.Server, int]:
    async def echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.read(1024)
        writer.write(data)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def _send_raw(port: int, payload: bytes, *, read_extra: bytes | None = None) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(payload)
    await writer.drain()
    head = await reader.readuntil(b"\r\n\r\n")
    body = b""
    if read_extra is not None:
        writer.write(read_extra)
        await writer.drain()
        body = await reader.read(1024)
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError):
        pass
    return head + body


def _forward_setup(tmp_path, echo_port: int):
    registry = IdentityRegistry(tmp_path / "identities.json")
    creds = registry.issue("acme", "bot")
    receipts: list[dict] = []
    policy = EgressPolicy(
        allow_hosts=["allowed.test"],
        allow_ports=[echo_port],
        block_private=False,  # the test upstream is loopback by necessity
        resolve=lambda host: ["127.0.0.1"],
    )
    proxy = ForwardProxy(
        policy=policy,
        registry=registry,
        recorder=lambda **f: receipts.append(f),
        require_identity=True,
    )
    return proxy, creds, receipts


def test_connect_tunnel_end_to_end(tmp_path):
    async def scenario():
        echo, echo_port = await _echo_server()
        proxy, creds, receipts = _forward_setup(tmp_path, echo_port)
        await proxy.start()
        try:
            payload = (
                f"CONNECT allowed.test:{echo_port} HTTP/1.1\r\n"
                f"Host: allowed.test:{echo_port}\r\n"
            ).encode() + _proxy_auth(creds.identity.spiffe_id, creds.token) + b"\r\n"
            got = await _send_raw(proxy.bound_port, payload, read_extra=b"ping")
            assert b"200 Connection Established" in got
            assert got.endswith(b"ping")  # tunnel relayed both ways
            assert receipts[-1]["verdict"] == "allow"
            assert receipts[-1]["actor"] == "spiffe://acme/agent/bot"
            assert receipts[-1]["action"] == "http_forward"
        finally:
            await proxy.stop()
            echo.close()
            await echo.wait_closed()

    asyncio.run(scenario())


def test_connect_unlisted_host_blocked(tmp_path):
    async def scenario():
        echo, echo_port = await _echo_server()
        proxy, creds, receipts = _forward_setup(tmp_path, echo_port)
        await proxy.start()
        try:
            payload = (
                f"CONNECT evil.test:{echo_port} HTTP/1.1\r\n"
            ).encode() + _proxy_auth(creds.identity.spiffe_id, creds.token) + b"\r\n"
            got = await _send_raw(proxy.bound_port, payload)
            assert b"403 Forbidden" in got
            assert BlockReason.HOST_NOT_ALLOWED.encode() in got
            assert receipts[-1]["block_reason"] == BlockReason.HOST_NOT_ALLOWED
        finally:
            await proxy.stop()
            echo.close()
            await echo.wait_closed()

    asyncio.run(scenario())


def test_connect_without_identity_407(tmp_path):
    async def scenario():
        echo, echo_port = await _echo_server()
        proxy, _, receipts = _forward_setup(tmp_path, echo_port)
        await proxy.start()
        try:
            got = await _send_raw(
                proxy.bound_port,
                f"CONNECT allowed.test:{echo_port} HTTP/1.1\r\n\r\n".encode(),
            )
            assert b"407 Proxy Authentication Required" in got
            assert receipts[-1]["block_reason"] == BlockReason.NO_IDENTITY
            assert receipts[-1]["actor"] == "anonymous"
        finally:
            await proxy.stop()
            echo.close()
            await echo.wait_closed()

    asyncio.run(scenario())


def test_connect_bad_token_407(tmp_path):
    async def scenario():
        echo, echo_port = await _echo_server()
        proxy, creds, _ = _forward_setup(tmp_path, echo_port)
        await proxy.start()
        try:
            payload = (
                f"CONNECT allowed.test:{echo_port} HTTP/1.1\r\n"
            ).encode() + _proxy_auth(creds.identity.spiffe_id, "wrong-token") + b"\r\n"
            got = await _send_raw(proxy.bound_port, payload)
            assert b"407" in got
        finally:
            await proxy.stop()
            echo.close()
            await echo.wait_closed()

    asyncio.run(scenario())


def test_non_connect_method_rejected(tmp_path):
    async def scenario():
        echo, echo_port = await _echo_server()
        proxy, creds, receipts = _forward_setup(tmp_path, echo_port)
        await proxy.start()
        try:
            payload = (
                b"GET http://allowed.test/ HTTP/1.1\r\n"
                + _proxy_auth(creds.identity.spiffe_id, creds.token)
                + b"\r\n"
            )
            got = await _send_raw(proxy.bound_port, payload)
            assert b"405 Method Not Allowed" in got
            assert receipts[-1]["block_reason"] == BlockReason.METHOD_NOT_ALLOWED
        finally:
            await proxy.stop()
            echo.close()
            await echo.wait_closed()

    asyncio.run(scenario())
