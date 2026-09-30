"""MCP transport shells — dumb pumps around :class:`McpSession`.

Two upstream flavours share one pump (``run_proxy``):

* :class:`StdioUpstream` — spawn the MCP server as a subprocess
  (``al mcp proxy -- npx some-server``) and speak newline-delimited JSON-RPC
  over its stdin/stdout.
* :class:`HttpUpstream` — POST each JSON-RPC message to a Streamable-HTTP MCP
  server (``al mcp proxy --url http://...``); JSON responses are queued back
  to the agent (SSE upstream responses are out of scope for the baseline).

The agent side is abstract (``recv_agent`` / ``send_agent`` callables) so the
CLI can wire real stdio while tests drive the pump in-memory. All security
decisions happen inside ``McpSession`` — a shell must never grow policy.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable

import httpx

from .session import McpSession, dump_line, parse_line

log = logging.getLogger("al.mcp.proxy")

RecvFn = Callable[[], Awaitable[dict[str, Any] | None]]
SendFn = Callable[[dict[str, Any]], Awaitable[None]]


class StdioUpstream:
    """An MCP server subprocess, newline-delimited JSON-RPC on its stdio."""

    def __init__(self, command: list[str]) -> None:
        self._command = command
        self._proc: asyncio.subprocess.Process | None = None

    async def start(self) -> None:
        self._proc = await asyncio.create_subprocess_exec(
            *self._command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )

    async def send(self, msg: dict[str, Any]) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        if self._proc.stdin.is_closing():
            return  # the agent has gone; nothing more is owed to the server
        self._proc.stdin.write(dump_line(msg).encode("utf-8"))
        await self._proc.stdin.drain()

    async def recv(self) -> dict[str, Any] | None:
        assert self._proc is not None and self._proc.stdout is not None
        while True:
            line = await self._proc.stdout.readline()
            if not line:
                return None  # EOF — server exited
            msg = parse_line(line.decode("utf-8", errors="replace"))
            if msg is not None:
                return msg

    async def close_input(self) -> None:
        """Agent went away: close the server's stdin so it finishes any
        in-flight replies and exits cleanly, rather than being killed mid-answer."""
        if self._proc is not None and self._proc.stdin is not None:
            self._proc.stdin.close()

    async def stop(self) -> None:
        if self._proc is not None and self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._proc.kill()


class HttpUpstream:
    """Streamable-HTTP MCP upstream: one POST per message, JSON replies queued."""

    _CLOSE = object()

    def __init__(self, url: str, *, client: httpx.AsyncClient | None = None) -> None:
        self._url = url
        self._client = client or httpx.AsyncClient(timeout=30.0)
        self._owns_client = client is None
        self._queue: asyncio.Queue[Any] = asyncio.Queue()

    async def start(self) -> None:  # symmetry with StdioUpstream
        return None

    async def send(self, msg: dict[str, Any]) -> None:
        resp = await self._client.post(
            self._url, json=msg,
            headers={"Accept": "application/json", "Content-Type": "application/json"})
        if resp.status_code == 202 or not resp.content:
            return  # notification accepted, nothing to relay
        try:
            payload = resp.json()
        except ValueError:
            log.warning("MCP HTTP upstream returned non-JSON (%s)", resp.status_code)
            return
        for m in payload if isinstance(payload, list) else [payload]:
            if isinstance(m, dict):
                await self._queue.put(m)

    async def recv(self) -> dict[str, Any] | None:
        item = await self._queue.get()
        return None if item is self._CLOSE else item

    async def close_input(self) -> None:
        """Agent went away. Every send() has already queued its response
        (sends are awaited in order), so ending the queue loses nothing."""
        await self._queue.put(self._CLOSE)

    async def stop(self) -> None:
        await self._queue.put(self._CLOSE)
        if self._owns_client:
            await self._client.aclose()


async def run_proxy(
    session: McpSession,
    upstream: StdioUpstream | HttpUpstream,
    recv_agent: RecvFn,
    send_agent: SendFn,
) -> None:
    """Pump until the agent closes its stream and the server drains.

    On agent EOF the upstream's *input* is closed (not the process): in-flight
    replies still arrive and are still filtered — a mediator that dropped the
    last response could drop the one carrying the attack."""
    await upstream.start()

    async def agent_pump() -> None:
        try:
            while (msg := await recv_agent()) is not None:
                out = session.filter_request(msg)
                if out.reply is not None:
                    await send_agent(out.reply)
                if out.forward is not None:
                    await upstream.send(out.forward)
        finally:
            await upstream.close_input()

    async def server_pump() -> None:
        while (msg := await upstream.recv()) is not None:
            out = session.filter_response(msg)
            if out.forward is not None:  # None = dropped by the session (receipted)
                await send_agent(out.forward)
            if out.reply is not None:  # a refused server request still gets an answer
                await upstream.send(out.reply)

    try:
        await asyncio.gather(agent_pump(), server_pump())
    finally:
        await upstream.stop()


__all__ = ["HttpUpstream", "StdioUpstream", "run_proxy"]
