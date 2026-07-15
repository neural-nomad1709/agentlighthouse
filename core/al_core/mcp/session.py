"""One mediated agent<->MCP-server conversation (transport-agnostic).

``McpSession`` filters JSON-RPC messages through :class:`McpMediator`; the
stdio and HTTP shells are dumb pumps around it, so every transport enforces
identically:

* ``tools/list`` **responses** — descriptors are pinned + poison-scanned;
  blocked tools are removed before the agent ever sees them (receipted).
* ``tools/call`` **requests** — authorized by the ActionGate (identity ->
  policy -> chain -> HITL). A denial never reaches the server; the agent gets
  a JSON-RPC error carrying the fixed ``block_reason`` (agent-legible denial,
  plus ``hitl_request_id`` when the call is parked for approval).
* ``tools/call`` **responses** — text content is scanned (the
  tool-response-injection attack, ASI01): block -> the result is **withheld**
  and replaced with an explainable error; strip -> text is redacted in place.
* Everything else (initialize, notifications, other methods) passes through —
  mediation must not break the protocol.

State per session: pending request-id -> method/tool maps, so responses can
be matched to what was asked. IDs are JSON-RPC ids (str | int).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..gateway.decision import BlockReason
from .descriptors import ToolDescriptor
from .mediator import McpMediator

_DENY_CODE = -32001  # implementation-defined JSON-RPC error space


@dataclass
class FilterOutcome:
    """What to do with one agent->server message: ``forward`` upstream (None =
    drop) and/or ``reply`` straight back to the agent (a denial)."""

    forward: dict[str, Any] | None = None
    reply: dict[str, Any] | None = None


def _text_of(result: dict[str, Any]) -> str:
    parts = []
    for item in result.get("content", []) or []:
        if isinstance(item, dict) and item.get("type") == "text":
            parts.append(item.get("text", ""))
    return "\n".join(p for p in parts if p)


class McpSession:
    def __init__(
        self,
        mediator: McpMediator,
        *,
        actor: str,
        session_id: str = "default",
    ) -> None:
        self._mediator = mediator
        self._actor = actor
        self._session_id = session_id
        self._pending: dict[Any, str] = {}    # request id -> method
        self._call_tool: dict[Any, str] = {}  # tools/call id -> tool name

    # -- agent -> server ---------------------------------------------------------

    def filter_request(self, msg: dict[str, Any]) -> FilterOutcome:
        method = msg.get("method")
        rid = msg.get("id")

        if method != "tools/call":
            if rid is not None and method:
                self._pending[rid] = method
            return FilterOutcome(forward=msg)

        params = msg.get("params") or {}
        tool = params.get("name") or ""
        args = params.get("arguments") or {}
        outcome = self._mediator.authorize_call(
            self._actor, tool, args, session_id=self._session_id)
        if not outcome.allowed:
            reason = outcome.decision.block_reason or BlockReason.TOOL_NOT_ALLOWED
            data: dict[str, Any] = {"block_reason": reason}
            if outcome.hitl_request_id:
                data["hitl_request_id"] = outcome.hitl_request_id
            return FilterOutcome(reply={
                "jsonrpc": "2.0", "id": rid,
                "error": {"code": _DENY_CODE,
                          "message": f"AgentLighthouse: tool call denied ({reason})",
                          "data": data},
            })
        if rid is not None:
            self._pending[rid] = method
            self._call_tool[rid] = tool

        # Outbound DLP may have redacted the arguments. Forward what the gate
        # returned, never what the agent sent — otherwise the redaction is a
        # report, not a control, and the secret still reaches the server.
        if outcome.redaction:
            msg = {**msg, "params": {**params, "arguments": outcome.args}}
        return FilterOutcome(forward=msg)

    # -- server -> agent ---------------------------------------------------------

    def filter_response(self, msg: dict[str, Any]) -> dict[str, Any]:
        rid = msg.get("id")
        method = self._pending.pop(rid, None) if rid is not None else None

        if method == "tools/list" and isinstance(msg.get("result"), dict):
            return self._filter_tools_list(msg)
        if method == "tools/call" and isinstance(msg.get("result"), dict):
            return self._filter_tool_result(msg, self._call_tool.pop(rid, ""))
        self._call_tool.pop(rid, None)
        return msg

    def _filter_tools_list(self, msg: dict[str, Any]) -> dict[str, Any]:
        tools = msg["result"].get("tools", []) or []
        descriptors = [
            ToolDescriptor(t.get("name", "?"), t.get("description", ""),
                           t.get("inputSchema"))
            for t in tools if isinstance(t, dict)
        ]
        review = self._mediator.review_tools(descriptors)
        allowed = {d.name for d in review.allowed}
        out = dict(msg)
        out["result"] = {**msg["result"],
                         "tools": [t for t in tools
                                   if isinstance(t, dict) and t.get("name") in allowed]}
        return out

    def _filter_tool_result(self, msg: dict[str, Any], tool: str) -> dict[str, Any]:
        result = msg["result"]
        text = _text_of(result)
        if not text:
            return msg
        scan = self._mediator.scan_result(
            text, actor=self._actor, tool=tool, session_id=self._session_id)
        if scan.blocked:
            reason = scan.block_reason or BlockReason.RESULT_BLOCKED
            out = dict(msg)
            out["result"] = {
                "content": [{"type": "text",
                             "text": f"[AgentLighthouse] tool result withheld ({reason})"}],
                "isError": True,
                "_al": {"block_reason": reason},
            }
            return out
        if scan.verdict == "strip":
            # Redacted text replaces the text parts; non-text parts survive.
            out = dict(msg)
            non_text = [i for i in result.get("content", []) or []
                        if not (isinstance(i, dict) and i.get("type") == "text")]
            out["result"] = {**result, "content":
                             [{"type": "text", "text": scan.text}, *non_text]}
            return out
        return msg


def parse_line(line: str) -> dict[str, Any] | None:
    """One newline-delimited JSON-RPC message; None for blank/garbage lines.

    Garbage from a server is dropped (fail-closed for content, tolerant for
    framing — a broken server must not crash the proxy)."""
    line = line.strip()
    if not line:
        return None
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        return None
    return msg if isinstance(msg, dict) else None


def dump_line(msg: dict[str, Any]) -> str:
    return json.dumps(msg, ensure_ascii=False, separators=(",", ":")) + "\n"


__all__ = ["FilterOutcome", "McpSession", "dump_line", "parse_line"]
