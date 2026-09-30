"""MCP mediation core (transport-agnostic).

Sits between an agent and an MCP server. Two responsibilities:

* **Tool discovery** (``review_tools``) — every advertised descriptor is
  pinned (rug-pull drift) and content-scanned (poisoning) before the agent is
  allowed to see it. A drifted or poisoned tool is dropped from the list the
  agent receives and receipted.
* **Tool invocation** — delegated to :class:`~al_core.capability.gate.ActionGate`
  (identity -> policy -> chain -> HITL) and, for results, its bidirectional
  ``scan_result``.

A stdio or Streamable-HTTP proxy is a thin transport shell over this core; the
security logic lives here and is unit-tested without a live server.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from ..detect import ContentGate, GateResult, ScanContext
from ..gateway.decision import BlockReason, Decision, finding
from .descriptors import ToolDescriptor, ToolPinner, scan_descriptor

if TYPE_CHECKING:  # avoid an import cycle: gate -> mcp.chain -> mcp -> mediator
    from ..capability.gate import ActionGate, ActionOutcome

Recorder = Callable[..., Any]


@dataclass
class ToolReview:
    descriptor: ToolDescriptor
    decision: Decision

    @property
    def allowed(self) -> bool:
        return self.decision.allowed


@dataclass
class ReviewResult:
    allowed: list[ToolDescriptor] = field(default_factory=list)
    blocked: list[ToolReview] = field(default_factory=list)

    @property
    def all_allowed(self) -> bool:
        return not self.blocked


class McpMediator:
    def __init__(
        self,
        action_gate: ActionGate,
        content_gate: ContentGate,
        *,
        pinner: ToolPinner | None = None,
        recorder: Recorder | None = None,
    ) -> None:
        self._gate = action_gate
        self._content = content_gate
        self._pinner = pinner or ToolPinner()
        self._record = recorder or (lambda **_: None)

    def review_tools(self, descriptors: list[ToolDescriptor]) -> ReviewResult:
        """Pin + poison-scan advertised tools. Blocked tools are withheld."""
        result = ReviewResult()
        for desc in descriptors:
            poison = scan_descriptor(desc, self._content)
            if not poison.allowed:
                self._reject(desc, poison)
                result.blocked.append(ToolReview(desc, poison))
                continue
            drift = self._pinner.check(desc)
            if not drift.allowed:
                self._reject(desc, drift)
                result.blocked.append(ToolReview(desc, drift))
                continue
            result.allowed.append(desc)
        return result

    def authorize_call(
        self, actor: str, tool: str, args: dict[str, Any] | None = None,
        *, session_id: str = "default", hitl_request_id: str | None = None,
    ) -> ActionOutcome:
        return self._gate.authorize(actor, tool, args, session_id=session_id,
                                    hitl_request_id=hitl_request_id)

    def scan_result(self, text: str, **kw) -> GateResult:
        return self._gate.scan_result(text, **kw)

    def approve(self, descriptor: ToolDescriptor) -> None:
        """Operator re-pins a drifted tool (un-block after review)."""
        self._pinner.approve(descriptor)

    def withhold_ambiguous(self, name: str) -> None:
        """Receipt a tool name advertised with conflicting descriptors."""
        self._record(actor="mcp", action="mcp_tool_call", target=f"tool:{name}",
                     verdict="block", block_reason=BlockReason.TOOL_DESCRIPTOR_DRIFT,
                     findings=[finding("mcp_pin", "mcp.descriptor_duplicate_name",
                                       "high", owasp="ASI04")])

    def deny_unadvertised(self, actor: str, tool: str, *, session_id: str) -> Decision:
        """Refuse and receipt a call to a tool the agent was not shown. A
        withheld (poisoned, drifted, ambiguous) tool must not be reachable by
        name: withholding it from the list is otherwise only advice."""
        decision = Decision.block(
            BlockReason.TOOL_NOT_ALLOWED,
            [finding("mcp_pin", "mcp.tool_not_advertised", "high", owasp="ASI04")])
        self._record(actor=actor, action="mcp_tool_call", target=f"tool:{tool}",
                     verdict="block", block_reason=decision.block_reason,
                     findings=decision.findings, session=session_id)
        return decision

    def scan_client_reply(self, text: str, *, actor: str, target: str,
                          session_id: str) -> GateResult:
        """Outbound DLP on the agent's answer to a server request (a sampling
        result, an elicitation response): it carries the agent's context to
        the server as surely as tool arguments do. Receipted like an argument
        scan; it does not taint the session (nothing hostile came in)."""
        result = self._content.scan_text(
            text, ScanContext(actor=actor, direction="outbound", target=target,
                              content_type="text/plain"))
        if result.blocked:
            self._record(actor=actor, action="mcp_client_reply", target=target,
                         verdict="block", block_reason=result.block_reason,
                         findings=result.findings, session=session_id)
        elif result.verdict in ("strip", "warn"):
            self._record(actor=actor, action="mcp_client_reply", target=target,
                         verdict=result.verdict, findings=result.findings,
                         redaction=result.redaction or None, session=session_id)
        return result

    def reject_message(self, actor: str, target: str, *, rule: str,
                       session_id: str, action: str = "mcp_tool_result") -> None:
        """Receipt a message dropped for a protocol violation: by default one
        from the server; ``action="mcp_client_reply"`` for one from the agent."""
        self._record(actor=actor, action=action, target=target,
                     verdict="block", block_reason=BlockReason.RESULT_BLOCKED,
                     findings=[finding("mcp_protocol", rule, "high", owasp="ASI01")],
                     session=session_id)

    def _reject(self, desc: ToolDescriptor, decision: Decision) -> None:
        self._record(actor="mcp", action="mcp_tool_call", target=f"tool:{desc.name}",
                     verdict="block", block_reason=decision.block_reason,
                     findings=decision.findings)


__all__ = ["McpMediator", "ReviewResult", "ToolReview"]
