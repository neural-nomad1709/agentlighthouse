"""Forward proxy (HTTP CONNECT) — zero-agent-code-change ingress.

Agents point ``HTTPS_PROXY`` at this listener. Only ``CONNECT`` is served;
identity is required (``Proxy-Authorization: Basic base64(spiffe_id:token)``)
unless config says otherwise, every tunnel decision goes through
:class:`~al_core.gateway.policy.EgressPolicy`, and the upstream connection is
made to the **pinned IP** (never a re-resolved name). Every decision — allow
or block — is receipted (action ``http_forward``).

TLS passes through opaquely (no MITM — deferred by design); the enforced
surface is *where* the tunnel may go, not what is said inside it.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import logging
from typing import Any, Callable

from ..identity import IdentityRegistry
from .decision import BlockReason, Decision, finding
from .policy import EgressPolicy

log = logging.getLogger("al.gateway.forward")

# recorder(**receipt_fields) — Runtime.record, or a test stub.
Recorder = Callable[..., Any]

_MAX_HEAD = 16 * 1024  # request line + headers cap (oversize head = hostile)
ANONYMOUS = "anonymous"


def _parse_head(head: bytes) -> tuple[str, str, dict[str, str]]:
    """(method, target, lowercased-headers) from a raw request head."""
    text = head.decode("latin-1")
    lines = text.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3:
        raise ValueError("malformed request line")
    method, target = parts[0].upper(), parts[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return method, target, headers


def _parse_connect_target(target: str) -> tuple[str, int]:
    """host, port from a CONNECT authority-form target ("host:port", "[v6]:port")."""
    if target.startswith("["):  # bracketed IPv6
        host, sep, port_s = target.rpartition("]:")
        if not sep:
            raise ValueError("IPv6 CONNECT target missing port")
        return host.lstrip("["), int(port_s)
    host, sep, port_s = target.rpartition(":")
    if not sep:
        raise ValueError("CONNECT target missing port")
    return host, int(port_s)


def _parse_proxy_auth(headers: dict[str, str]) -> tuple[str, str] | None:
    """(spiffe_id, token) from Proxy-Authorization: Basic, or None."""
    value = headers.get("proxy-authorization", "")
    scheme, _, blob = value.partition(" ")
    if scheme.lower() != "basic" or not blob:
        return None
    try:
        decoded = base64.b64decode(blob.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    # Split on the LAST colon: spiffe ids contain "://", tokens never contain ":".
    sid, sep, token = decoded.rpartition(":")
    if not sep:
        return None
    return sid, token


class ForwardProxy:
    """One asyncio TCP server; safe to start/stop from the running loop."""

    def __init__(
        self,
        *,
        policy: EgressPolicy,
        registry: IdentityRegistry,
        recorder: Recorder,
        require_identity: bool = True,
        connect_timeout_s: float = 30.0,
        killswitch: "Callable[[], bool] | None" = None,
    ) -> None:
        self._policy = policy
        self._registry = registry
        self._record = recorder
        self._require_identity = require_identity
        self._connect_timeout = connect_timeout_s
        self._killswitch = killswitch or (lambda: False)
        self._server: asyncio.Server | None = None

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> "ForwardProxy":
        self._server = await asyncio.start_server(self._handle, host, port)
        return self

    @property
    def bound_port(self) -> int:
        assert self._server is not None
        return self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    # -- per-connection ------------------------------------------------------

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await self._serve(reader, writer)
        except Exception:  # noqa: BLE001 — one bad client must not kill the server
            log.exception("forward proxy connection failed")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            await self._reply(writer, 400, "Bad Request", BlockReason.INVALID_URL)
            return
        if len(head) > _MAX_HEAD:
            await self._reply(writer, 400, "Bad Request", BlockReason.INVALID_URL)
            return

        try:
            method, target, headers = _parse_head(head[:-4])
        except ValueError:
            await self._reply(writer, 400, "Bad Request", BlockReason.INVALID_URL)
            return

        # Kill switch: full deny-all, before identity or policy. Not receipted
        # per-request (the engagement is the signed standing decision).
        if self._killswitch():
            await self._reply(writer, 503, "Service Unavailable",
                              BlockReason.KILLSWITCH_ENGAGED)
            return

        # Identity first: an unauthenticated caller learns nothing about policy.
        actor = ANONYMOUS
        creds = _parse_proxy_auth(headers)
        if creds is not None:
            ident = self._registry.authenticate(*creds)
            if ident is not None:
                actor = ident.spiffe_id
        if actor == ANONYMOUS and self._require_identity:
            await self._receipt(
                actor,
                target,
                Decision.block(
                    BlockReason.NO_IDENTITY,
                    [finding("egress_policy", "identity.missing", "high", owasp="ASI03")],
                ),
            )
            await self._reply(
                writer, 407, "Proxy Authentication Required", BlockReason.NO_IDENTITY
            )
            return

        if method != "CONNECT":
            await self._receipt(
                actor, target, Decision.block(BlockReason.METHOD_NOT_ALLOWED)
            )
            await self._reply(writer, 405, "Method Not Allowed", BlockReason.METHOD_NOT_ALLOWED)
            return

        try:
            host, port = _parse_connect_target(target)
        except ValueError:
            await self._receipt(actor, target, Decision.block(BlockReason.INVALID_URL))
            await self._reply(writer, 400, "Bad Request", BlockReason.INVALID_URL)
            return

        decision = self._policy.check_connect(host, port)
        await self._receipt(actor, f"{host}:{port}", decision)
        if not decision.allowed:
            await self._reply(writer, 403, "Forbidden", decision.block_reason)
            return

        assert decision.pin is not None
        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection(decision.pin.ip, port),
                timeout=self._connect_timeout,
            )
        except (OSError, asyncio.TimeoutError):
            await self._reply(writer, 502, "Bad Gateway", None)
            return

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        try:
            await asyncio.gather(
                self._pipe(reader, up_writer), self._pipe(up_reader, writer)
            )
        finally:
            up_writer.close()
            try:
                await up_writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    @staticmethod
    async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                if writer.can_write_eof():
                    writer.write_eof()
            except (ConnectionError, OSError):
                pass

    async def _reply(
        self, writer: asyncio.StreamWriter, code: int, phrase: str, reason: str | None
    ) -> None:
        headers = f"HTTP/1.1 {code} {phrase}\r\nConnection: close\r\n"
        if reason:
            headers += f"X-AL-Block-Reason: {reason}\r\n"
        if code == 407:
            headers += 'Proxy-Authenticate: Basic realm="agentlighthouse"\r\n'
        writer.write((headers + "Content-Length: 0\r\n\r\n").encode("latin-1"))
        await writer.drain()

    async def _receipt(self, actor: str, target: str, decision: Decision) -> None:
        # Ledger writes are blocking (file + SQLite); keep the loop responsive.
        await asyncio.to_thread(
            self._record,
            actor=actor,
            action="http_forward",
            target=target,
            verdict=decision.verdict,
            block_reason=decision.block_reason,
            findings=decision.findings,
        )


__all__ = ["ANONYMOUS", "ForwardProxy", "Recorder"]
