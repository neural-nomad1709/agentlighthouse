"""One mediated agent<->MCP-server conversation (transport-agnostic).

``McpSession`` filters JSON-RPC messages through :class:`McpMediator`; the
stdio and HTTP shells are dumb pumps around it, so every transport enforces
identically:

* ``tools/list`` **responses** — descriptors are pinned + poison-scanned;
  blocked tools are removed before the agent ever sees them (receipted). Two
  different descriptors under one name are ambiguous (the agent cannot tell
  which one the server will run) and both are withheld; identical repeats
  collapse to one.
* **The advertised tools are an allow-list.** A ``tools/call`` naming a tool
  that was not in the last ``tools/list`` the agent received is denied before
  the gate (receipted): a withheld tool must not be reachable by name. A list
  requested without a ``cursor`` replaces the set; a paginated page adds to
  it. ``notifications/tools/list_changed`` clears it, so the agent must list
  again. A call before any list is denied.
* ``tools/call`` **requests** — authorized by the ActionGate (identity ->
  policy -> chain -> HITL). A denial never reaches the server; the agent gets
  a JSON-RPC error carrying the fixed ``block_reason`` (agent-legible denial,
  plus ``hitl_request_id`` when the call is parked for approval). Once a human
  approves, the agent retries the same call (optionally naming the request in
  ``params._meta["agentlighthouse/hitl_request_id"]``) and it is forwarded.
* ``tools/call`` **responses** — every string in the result is scanned (the
  tool-response-injection attack, ASI01): text blocks, embedded resources,
  ``structuredContent``, ``_meta``. A base64 ``blob``/``data`` field is decoded
  and scanned when it is UTF-8 text; binary media is skipped. block -> the
  result is **withheld** and replaced with an explainable error; strip ->
  strings are redacted in place. A content block of unknown ``type`` is
  withheld (a new kind of content must not arrive unscanned).
* **Every other reply is scanned too** (``initialize`` instructions,
  ``resources/read``, ``prompts/get``, list descriptions, ...): scanning is the
  default, not a per-method opt-in, so a method nobody listed is still covered.
  A blocked reply becomes a JSON-RPC error.
* **Response ids are an allow-list.** A server reply is relayed only if it
  answers a request that is still in flight, exactly once. A duplicate or
  unknown id is dropped (receipted): otherwise the second answer to a scanned
  call, or an answer to nothing, would reach the agent unscanned. The agent may
  not reuse an id that is still in flight either, since that would relabel
  what the pending reply is scanned as.
* **Server-initiated messages** (``sampling/createMessage``, elicitation,
  notifications) flow into the agent's context too, so every string in them is
  scanned; a blocked one is dropped, a stripped one is redacted. A blocked
  *request* is still answered (``FilterOutcome.reply``), or the server waits
  on it forever: ``elicitation/create`` with the spec's ``{"action":
  "decline"}``, anything else with a JSON-RPC error.
* **The agent's replies to server requests** are an allow-list: one is
  forwarded only if it answers a request the agent was shown, once. It is
  DLP-scanned on the way out (a sampling result carries the agent's context
  to the server); a blocked one is replaced by a refusal, so the server still
  gets an answer. Receipted as ``mcp_client_reply``.
* Error replies are scanned the same way. A clean reply passes through
  byte-for-byte — mediation must not break the protocol.

State per session: pending request-id -> method/tool maps, so responses can
be matched to what was asked, and the set of advertised tool names. IDs are
JSON-RPC ids (str | int).
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import unquote

from ..detect import GateResult
from ..gateway.decision import BlockReason
from .descriptors import ToolDescriptor
from .mediator import McpMediator

_DENY_CODE = -32001  # implementation-defined JSON-RPC error space
_INVALID_REQUEST = -32600  # JSON-RPC 2.0: the message is not a valid request

#: Where an agent may name the approval it is retrying under.
HITL_META_KEY = "agentlighthouse/hitl_request_id"


@dataclass
class FilterOutcome:
    """What to do with one message, in either direction: ``forward`` it on to
    its recipient (None = drop) and/or ``reply`` straight back to its sender
    (a denial to the agent, a refusal to the server). A transport must send
    both; neither is optional."""

    forward: dict[str, Any] | None = None
    reply: dict[str, Any] | None = None


#: MCP tool-result content block types; anything else is withheld.
_CONTENT_TYPES = frozenset({"text", "image", "audio", "resource", "resource_link"})


_URI_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:(\S*)")
_MIME_RE = re.compile(r"[\w.+-]+/[\w.+-]+(?:\s*;\s*[\w.+-]+=[\w.+\"-]+)*")


def _scan_view(key: str | None, value: str) -> str:
    """The part of a string the scan sees. A resource ``uri`` is scanned
    without its scheme, percent-decoded: ``file://`` — the scheme of every
    filesystem MCP server — trips the dangerous-scheme rule, but prose hidden
    in the rest of the URI is still read. A well-formed ``mimeType`` is a
    label, not prose. Anything else, including a ``uri`` that does not parse,
    is scanned as it is."""
    if key == "uri" and (m := _URI_RE.fullmatch(value)):
        return unquote(m.group(1)).lstrip("/")
    if key == "mimeType" and _MIME_RE.fullmatch(value):
        return ""
    return value


def _is_binary_field(obj: dict[str, Any], key: str) -> bool:
    """A base64 payload: a resource ``blob``, or image/audio ``data``."""
    return key == "blob" or (key == "data" and obj.get("type") in ("image", "audio"))


def _decode_text(value: str) -> tuple[str | None, bool]:
    """``(text, was_base64)`` for a binary field. A payload that decodes to
    UTF-8 is text whatever its ``mimeType`` claims, so it is scanned; one that
    does not is binary media (None) and is skipped — scanning base64 as a
    string only trips the entropy scanners. A value that is not base64 at all
    is already text."""
    try:
        raw = base64.b64decode("".join(value.split()), validate=True)
    except (binascii.Error, ValueError):
        return value, False
    try:
        return raw.decode("utf-8"), True
    except UnicodeDecodeError:
        return None, True


def _refusal(method: str, rid: Any, message: str, reason: str | None = None,
             code: int = _DENY_CODE) -> dict[str, Any]:
    """An answer refusing a server request. Elicitation has a spec answer for
    "no" (``{"action": "decline"}``), which a client-side form would give;
    anything else gets a JSON-RPC error."""
    if method == "elicitation/create":
        result: dict[str, Any] = {"action": "decline"}
        if reason:
            result["_meta"] = {"agentlighthouse/block_reason": reason}
        return {"jsonrpc": "2.0", "id": rid, "result": result}
    return _rpc_error(rid, code, message, {"block_reason": reason} if reason else None)


def _is_valid_id(rid: Any) -> bool:
    # JSON-RPC ids are strings or numbers. bool is an int subclass in Python
    # (True == 1), and a list/dict is unhashable; both are refused.
    return isinstance(rid, str) or (isinstance(rid, int) and not isinstance(rid, bool))


def _rpc_error(rid: Any, code: int, message: str, data: dict[str, Any] | None = None,
               ) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": rid, "error": error}


class _Withheld(Exception):
    """Internal: a scanned string was blocked (unwinds the payload walk)."""

    def __init__(self, reason: str) -> None:
        self.reason = reason


class McpSession:
    def __init__(
        self,
        mediator: McpMediator,
        *,
        actor: str,
        session_id: str = "default",
        max_in_flight: int = 1024,
    ) -> None:
        self._mediator = mediator
        # Bounds each direction's unanswered requests: a peer that never
        # answers must not grow the session's memory without limit.
        self._max_in_flight = max_in_flight
        self._actor = actor
        self._session_id = session_id
        self._pending: dict[Any, str] = {}    # request id -> method
        self._call_tool: dict[Any, str] = {}  # tools/call id -> tool name
        self._list_page: dict[Any, bool] = {}  # tools/list id -> continues a paginated list
        # Tool names the agent was shown; None until it has listed tools.
        self._advertised: set[str] | None = None
        self._server_pending: dict[Any, str] = {}  # server request id shown to the agent -> method

    # -- agent -> server ---------------------------------------------------------

    def filter_request(self, msg: dict[str, Any]) -> FilterOutcome:
        method = msg.get("method")
        rid = msg.get("id")

        if not method and rid is not None and ("result" in msg or "error" in msg):
            return self._filter_agent_reply(msg, rid)

        if method and rid is not None:
            if not _is_valid_id(rid):
                return FilterOutcome(reply=_rpc_error(
                    None, _INVALID_REQUEST, "AgentLighthouse: invalid request id"))
            if rid in self._pending:
                return FilterOutcome(reply=_rpc_error(
                    rid, _INVALID_REQUEST,
                    "AgentLighthouse: request id is already in flight"))
            if len(self._pending) >= self._max_in_flight:
                return FilterOutcome(reply=_rpc_error(
                    rid, _INVALID_REQUEST,
                    "AgentLighthouse: too many requests in flight"))

        if method != "tools/call":
            if rid is not None and method:
                self._pending[rid] = method
                if method == "tools/list":
                    params = msg.get("params")
                    self._list_page[rid] = isinstance(params, dict) and bool(params.get("cursor"))
            return FilterOutcome(forward=msg)

        params = msg.get("params") or {}
        tool = params.get("name") or ""
        if (not isinstance(tool, str) or self._advertised is None
                or tool not in self._advertised):
            decision = self._mediator.deny_unadvertised(
                self._actor, tool, session_id=self._session_id)
            return FilterOutcome(reply=_rpc_error(
                rid, _DENY_CODE,
                f"AgentLighthouse: tool call denied ({decision.block_reason}): "
                "the tool is not in the current tools/list; call tools/list first",
                {"block_reason": decision.block_reason}))
        args = params.get("arguments") or {}
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        named = meta.get(HITL_META_KEY)
        outcome = self._mediator.authorize_call(
            self._actor, tool, args, session_id=self._session_id,
            hitl_request_id=named if isinstance(named, str) else None)
        if not outcome.allowed:
            reason = outcome.decision.block_reason or BlockReason.TOOL_NOT_ALLOWED
            data: dict[str, Any] = {"block_reason": reason}
            if outcome.hitl_request_id:
                data["hitl_request_id"] = outcome.hitl_request_id
            return FilterOutcome(reply=_rpc_error(
                rid, _DENY_CODE, f"AgentLighthouse: tool call denied ({reason})", data))
        if rid is not None:
            self._pending[rid] = method
            self._call_tool[rid] = tool

        # Outbound DLP may have redacted the arguments. Forward what the gate
        # returned, never what the agent sent — otherwise the redaction is a
        # report, not a control, and the secret still reaches the server.
        if outcome.redaction:
            msg = {**msg, "params": {**params, "arguments": outcome.args}}
        return FilterOutcome(forward=msg)

    def _filter_agent_reply(self, msg: dict[str, Any], rid: Any) -> FilterOutcome:
        """The agent answering a server request. Forwarded only if it answers
        one the agent was shown and nobody has answered yet: a request we
        blocked was already answered by us, and an answer to nothing is a
        message the server never asked for. Then DLP-scanned outbound."""
        method = self._server_pending.pop(rid, None) if _is_valid_id(rid) else None
        if method is None:
            self._mediator.reject_message(
                self._actor, f"mcp:client-reply:{rid!r}"[:200],
                rule="mcp.reply.unmatched_id", session_id=self._session_id,
                action="mcp_client_reply")
            return FilterOutcome()
        target = f"mcp:{method}:reply"

        def scan(text: str) -> GateResult:
            return self._mediator.scan_client_reply(
                text, actor=self._actor, target=target, session_id=self._session_id)

        try:
            return FilterOutcome(forward=self._scan_payload(msg, scan))
        except _Withheld as withheld:
            # The server is waiting on this id: answer it, without the payload.
            return FilterOutcome(forward=_refusal(
                method, rid, f"AgentLighthouse: {method} reply withheld ({withheld.reason})",
                withheld.reason))

    def abandon(self, rid: Any) -> None:
        """Forget an in-flight request whose reply will never arrive (the
        transport failed, or the upstream accepted it without answering), so
        the agent may retry under the same id."""
        if _is_valid_id(rid):
            self._pending.pop(rid, None)
            self._call_tool.pop(rid, None)
            self._list_page.pop(rid, None)

    # -- server -> agent ---------------------------------------------------------

    def filter_response(self, msg: dict[str, Any]) -> FilterOutcome:
        """What to do with one server->agent message: ``forward`` it to the
        agent and/or ``reply`` to the server (a refused server request)."""
        if msg.get("method"):
            return self._filter_server_message(msg)

        rid = msg.get("id")
        if not _is_valid_id(rid) or rid not in self._pending:
            self._mediator.reject_message(
                self._actor, f"mcp:response:{rid!r}"[:200],
                rule="mcp.response.unmatched_id", session_id=self._session_id)
            return FilterOutcome()
        method = self._pending.pop(rid)
        tool = self._call_tool.pop(rid, "")
        continues_list = self._list_page.pop(rid, False)
        return FilterOutcome(forward=self._filter_answer(
            msg, rid, method, tool, continues_list=continues_list))

    def _filter_answer(self, msg: dict[str, Any], rid: Any, method: str, tool: str,
                       *, continues_list: bool) -> dict[str, Any]:
        """The server's answer to an agent request, as the agent may see it."""
        if "result" not in msg:
            return self._filter_error(msg, tool or method)
        if method == "tools/list":
            if not isinstance(msg["result"], dict):
                return _rpc_error(rid, _DENY_CODE,
                                  "AgentLighthouse: malformed tools/list result withheld")
            return self._filter_tools_list(msg, continues=continues_list)
        if method == "tools/call":
            if not isinstance(msg["result"], dict):
                return self._withheld_result(msg, BlockReason.RESULT_BLOCKED)
            return self._filter_tool_result(msg, tool)
        return self._filter_reply(msg, method)

    def _filter_reply(self, msg: dict[str, Any], method: str) -> dict[str, Any]:
        """Any other method's reply. Its strings reach the agent's context as
        surely as a tool result's do (resources/read, prompts/get, initialize
        instructions, list descriptions), so it gets the same scan."""
        try:
            return self._scan_payload(msg, self._inbound(f"mcp:{method}"))
        except _Withheld as withheld:
            return _rpc_error(msg.get("id"), _DENY_CODE,
                              f"AgentLighthouse: {method} reply withheld ({withheld.reason})",
                              {"block_reason": withheld.reason})

    def _filter_tools_list(self, msg: dict[str, Any], *, continues: bool) -> dict[str, Any]:
        tools = msg["result"].get("tools", []) or []
        # First-seen order; identical repeats collapse, conflicting ones are
        # withheld as a group. A name is only safe to advertise if exactly one
        # descriptor claims it — the verdict for one twin must never admit the
        # other.
        groups: dict[str, list[dict[str, Any]]] = {}
        for t in tools:
            if isinstance(t, dict) and isinstance(t.get("name"), str) and t["name"]:
                group = groups.setdefault(t["name"], [])
                if t not in group:
                    group.append(t)
        unique: list[dict[str, Any]] = []
        for name, group in groups.items():
            if len(group) == 1:
                unique.append(group[0])
            else:
                self._mediator.withhold_ambiguous(name)
        descriptors = [ToolDescriptor(t["name"], t.get("description", ""),
                                      t.get("inputSchema"))
                       for t in unique]
        review = self._mediator.review_tools(descriptors)
        allowed = {id(d) for d in review.allowed}
        shown = [t for t, d in zip(unique, descriptors) if id(d) in allowed]
        names = {t["name"] for t in shown}
        withheld = set(groups) - names
        # A later page adds to the list; a list from the start replaces it, so
        # a tool withheld now (drift) is no longer callable from an old list.
        # A later page also revokes any name it withheld: a different twin of
        # an earlier page's tool is D2 across pages, and the server may run
        # either one.
        if continues:
            self._advertised = ((self._advertised or set()) | names) - withheld
        else:
            self._advertised = names
        out = dict(msg)
        out["result"] = {**msg["result"], "tools": shown}
        return out

    def _filter_tool_result(self, msg: dict[str, Any], tool: str) -> dict[str, Any]:
        content = msg["result"].get("content")
        if content is not None and not (
                isinstance(content, list)
                and all(isinstance(i, dict) and i.get("type") in _CONTENT_TYPES
                        for i in content)):
            self._mediator.reject_message(
                self._actor, f"tool:{tool}:result",
                rule="mcp.result.unknown_content_type", session_id=self._session_id)
            return self._withheld_result(msg, BlockReason.RESULT_BLOCKED)
        try:
            return self._scan_payload(msg, self._inbound(tool))
        except _Withheld as withheld:
            return self._withheld_result(msg, withheld.reason)

    @staticmethod
    def _withheld_result(msg: dict[str, Any], reason: str) -> dict[str, Any]:
        out = {k: v for k, v in msg.items() if k != "error"}
        out["result"] = {
            "content": [{"type": "text",
                         "text": f"[AgentLighthouse] tool result withheld ({reason})"}],
            "isError": True,
            "_al": {"block_reason": reason},
        }
        return out

    def _filter_error(self, msg: dict[str, Any], label: str) -> dict[str, Any]:
        try:
            return self._scan_payload(msg, self._inbound(label))
        except _Withheld as withheld:
            return _rpc_error(msg.get("id"), _DENY_CODE,
                              f"AgentLighthouse: error reply withheld ({withheld.reason})",
                              {"block_reason": withheld.reason})

    def _filter_server_message(self, msg: dict[str, Any]) -> FilterOutcome:
        """A server-initiated request or notification. Its strings land in the
        agent's (or its LLM's) context, so they get the tool-result scan. A
        refused request is answered; a refused notification needs no answer."""
        if msg.get("method") == "notifications/tools/list_changed":
            # The server's tools changed: calls wait for a fresh, reviewed list.
            # Cleared even if the scan drops the notification.
            self._advertised = None
        method = msg.get("method")
        rid = msg.get("id")
        try:
            out = self._scan_payload(msg, self._inbound(f"server:{method}"))
        except _Withheld as withheld:
            # scan_result already receipted the block. A request (it has an
            # id) still needs an answer, or the server waits on it forever.
            if rid is None:
                return FilterOutcome()
            return FilterOutcome(reply=_refusal(
                method, rid, f"AgentLighthouse: {method} request withheld ({withheld.reason})",
                withheld.reason))
        if _is_valid_id(rid):
            if len(self._server_pending) >= self._max_in_flight:
                return FilterOutcome(reply=_refusal(
                    method, rid, "AgentLighthouse: too many server requests awaiting the agent",
                    code=_INVALID_REQUEST))
            self._server_pending[rid] = method
        return FilterOutcome(forward=out)

    def _inbound(self, label: str) -> Callable[[str], GateResult]:
        """The tool-result scan for server content (it taints the session on
        a hostile hit)."""
        return lambda text: self._mediator.scan_result(
            text, actor=self._actor, tool=label, session_id=self._session_id)

    def _scan_payload(self, msg: dict[str, Any],
                      scan: Callable[[str], GateResult]) -> dict[str, Any]:
        """Scan every string in ``msg`` (except the envelope) with ``scan``.
        The block decision is made on joined text, as for a tool result, so a
        payload split across fields is still seen whole. Raises ``_Withheld``
        on a block; returns ``msg`` with stripped strings redacted otherwise."""
        envelope = ("jsonrpc", "id", "method")
        body = {k: v for k, v in msg.items() if k not in envelope}

        def strings(value: Any, key: str | None = None) -> list[tuple[str | None, str]]:
            if isinstance(value, str):
                view = _scan_view(key, value)
                return [(key, view)] if view else []
            if isinstance(value, dict):
                found: list[tuple[str | None, str]] = []
                for k, v in value.items():
                    if isinstance(v, str) and _is_binary_field(value, k):
                        text, _ = _decode_text(v)
                        if text:  # decoded text is prose the agent will read
                            found.append(("text", text))
                    else:
                        found.extend(strings(v, k))
                return found
            if isinstance(value, list):
                return [s for v in value for s in strings(v, key)]
            return []

        found = strings(body)
        # Two views: every string, and the prose alone (MCP content blocks keep
        # it under "text"), so structural fields like "role"/"type" cannot sit
        # between the halves of a split payload.
        views = ("\n".join(v for _, v in found),
                 "\n".join(v for k, v in found if k == "text"))
        verdicts = []
        for text in views:
            if not text:
                continue
            result = scan(text)
            if result.blocked:
                raise _Withheld(result.block_reason or BlockReason.RESULT_BLOCKED)
            verdicts.append(result.verdict)
        if "strip" not in verdicts:
            return msg

        def redact_text(value: str) -> str:
            return scan(value).text

        def redact_binary(value: str) -> str:
            text, was_base64 = _decode_text(value)
            if not text:
                return value  # binary media, or empty
            clean = redact_text(text)
            if clean == text:
                return value  # untouched: keep the original encoding
            return base64.b64encode(clean.encode("utf-8")).decode("ascii") if was_base64 else clean

        def redact(value: Any, key: str | None = None) -> Any:
            if isinstance(value, str) and value:
                # A uri or mimeType is kept whole: a redacted one names
                # nothing. It was scanned, so a block would have fired.
                return value if _scan_view(key, value) != value else redact_text(value)
            if isinstance(value, dict):
                return {k: (redact_binary(v) if isinstance(v, str) and _is_binary_field(value, k)
                            else redact(v, k))
                        for k, v in value.items()}
            if isinstance(value, list):
                return [redact(v, key) for v in value]
            return value

        return {k: (v if k in envelope else redact(v)) for k, v in msg.items()}


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


__all__ = ["FilterOutcome", "HITL_META_KEY", "McpSession", "dump_line", "parse_line"]
