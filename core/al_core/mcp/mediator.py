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

from ..detect import ContentGate, GateResult
from ..gateway.decision import Decision
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
        *, session_id: str = "default",
    ) -> ActionOutcome:
        return self._gate.authorize(actor, tool, args, session_id=session_id)

    def scan_result(self, text: str, **kw) -> GateResult:
        return self._gate.scan_result(text, **kw)

    def approve(self, descriptor: ToolDescriptor) -> None:
        """Operator re-pins a drifted tool (un-block after review)."""
        self._pinner.approve(descriptor)

    def _reject(self, desc: ToolDescriptor, decision: Decision) -> None:
        self._record(actor="mcp", action="mcp_tool_call", target=f"tool:{desc.name}",
                     verdict="block", block_reason=decision.block_reason,
                     findings=decision.findings)


__all__ = ["McpMediator", "ReviewResult", "ToolReview"]
