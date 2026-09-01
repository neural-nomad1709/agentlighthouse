"""ActionGate (L4) — one decision point for every tool call.

Ties the Phase-3 pieces into a single ``authorize`` call, applied in
fail-closed order:

1. **Identity** — no actor / unregistered actor -> deny (``NO_IDENTITY_TOOL``).
2. **Tool policy** — identity-bound default-deny + argument constraints.
3. **Chain detection** — record the call; a completed recon->exfil chain denies
   and taints the session.
4. **HITL** — irreversible verbs (and, in a tainted session, protected verbs)
   pause for human approval; the outcome carries the request id.

A separate ``scan_result`` runs tool *output* back through the content gate
(bidirectional scanning) and taints the session on untrusted/injection-bearing
results, so a later protected call in the same session is escalated.

Every decision is receipted (``mcp_tool_call`` / ``mcp_tool_result``) through
an injected recorder, so the whole flow is evidence-backed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from ..detect import ContentGate, GateResult, ScanContext
from ..gateway.decision import BlockReason, Decision, finding
from .budget import BudgetTracker
from .hitl import HitlGate
from .policy import ToolCall, ToolPolicy
from .taint import TaintSource, TaintTracker
from ..mcp.chain import ChainDetector

Recorder = Callable[..., Any]


class _ArgBlocked(Exception):
    """Internal: a tool argument tripped a blocking scanner (unwinds the walk)."""

    def __init__(self, result: GateResult) -> None:
        self.result = result


@dataclass
class ActionOutcome:
    """Result of authorizing a tool call. ``hitl_request_id`` is set when the
    call is held for approval (verdict block, reason ``HITL_REQUIRED``).

    ``args`` is what the tool may actually be called with: the original
    arguments, or a **redacted** copy when outbound DLP stripped something from
    them. Callers must forward ``outcome.args``, not the arguments they passed
    in — that is how a redaction actually takes effect on the wire.
    """

    decision: Decision
    hitl_request_id: str | None = None
    args: dict[str, Any] = field(default_factory=dict)
    redaction: dict[str, int] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision.allowed


class ActionGate:
    def __init__(
        self,
        policy: ToolPolicy,
        *,
        chain: ChainDetector | None = None,
        hitl: HitlGate | None = None,
        taint: TaintTracker | None = None,
        content_gate: ContentGate | None = None,
        recorder: Recorder | None = None,
        known_actor: Callable[[str], bool] | None = None,
        killswitch: Callable[[], bool] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._policy = policy
        self._chain = chain or ChainDetector()
        self._hitl = hitl or HitlGate()
        self._taint = taint or TaintTracker()
        self._gate = content_gate
        self._record = recorder or (lambda **_: None)
        self._budget = BudgetTracker(clock=clock)
        # By default any non-empty actor is accepted (transport already
        # authenticated it); pass a registry membership check to tighten.
        self._known_actor = known_actor or (lambda a: bool(a))
        self._killswitch = killswitch or (lambda: False)

    @property
    def hitl(self) -> HitlGate:
        return self._hitl

    @property
    def taint(self) -> TaintTracker:
        return self._taint

    def authorize(
        self, actor: str, tool: str, args: dict[str, Any] | None = None,
        *, session_id: str = "default",
    ) -> ActionOutcome:
        args = args or {}
        target = f"tool:{tool}"

        # 0. Kill switch: full deny-all, before anything else.
        if self._killswitch():
            return self._deny(actor, target, Decision.block(
                BlockReason.KILLSWITCH_ENGAGED,
                [finding("killswitch", "killswitch.engaged", "critical")],
            ), session=session_id)

        # 1. Identity.
        if not actor or not self._known_actor(actor):
            return self._deny(actor, target, Decision.block(
                BlockReason.NO_IDENTITY_TOOL,
                [finding("tool_policy", "policy.no_identity", "high", owasp="ASI03")],
            ), session=session_id)

        # 2. Tool policy (default-deny + arg constraints).
        decision = self._policy.check(ToolCall(actor=actor, tool=tool, args=args))
        if not decision.allowed:
            return self._deny(actor, target, decision, session=session_id)

        # 3. Outbound DLP on the ARGUMENTS themselves.
        #
        # Policy proves the *shape* of a call is permitted (allowed tool, allowed
        # host, path under /workspace, value in range). It says nothing about
        # what the agent put *inside* those arguments. An agent legitimately
        # allowed to http_post to an allow-listed host can carry the system
        # prompt, the conversation, or an AWS key out in the request body — a
        # permitted call, exfiltrating context. So the arguments get the same
        # content gate the reverse proxy already applies to outbound prompts.
        blocked, args, redaction, findings = self._scan_args(
            actor, tool, target, args, session=session_id)
        if blocked is not None:
            return blocked

        # 4. Chain detection.
        chain_block = self._chain.record(session_id, tool)
        if chain_block is not None:
            self._taint.mark(session_id, TaintSource.UNPINNED_TOOL_RESULT)
            return self._deny(actor, target, chain_block, session=session_id)

        # 5. HITL for irreversible / (tainted) protected verbs.
        tainted = self._taint.is_tainted(session_id)
        if self._hitl.requires_approval(tool, tainted=tainted):
            req = self._hitl.submit(actor, tool)
            decision = self._hitl.decision(req.request_id)  # HITL_REQUIRED (pending)
            self._record(actor=actor, action="mcp_tool_call", target=target,
                         verdict="ask", block_reason=decision.block_reason,
                         findings=decision.findings, session=session_id)
            return ActionOutcome(decision=decision, hitl_request_id=req.request_id,
                                 args=args, redaction=redaction)

        # Per-actor rate budget — the last gate, so a slot is consumed only by
        # a call that will actually proceed. A call denied by policy/DLP/chain
        # returned earlier, and one held for HITL returned above; none of them
        # counts. The N+1th executing call in the rolling minute fails closed
        # with a retryable BUDGET_EXCEEDED.
        limit = self._policy.budget_for(actor)
        if limit is not None and not self._budget.check_and_consume(actor, limit):
            return self._deny(actor, target, Decision.block(
                BlockReason.BUDGET_EXCEEDED,
                [finding("tool_policy", "policy.budget_exceeded", "medium",
                         owasp="ASI08")],
            ), session=session_id)

        # A redaction is an ALLOW with the payload removed — the call proceeds
        # with the placeholder. Only a blocking verdict stops it (above).
        self._record(actor=actor, action="mcp_tool_call", target=target,
                     verdict="strip" if redaction else "allow",
                     findings=findings or None, redaction=redaction or None,
                     session=session_id)
        return ActionOutcome(decision=Decision.allow(), args=args, redaction=redaction)

    def _scan_args(
        self, actor: str, tool: str, target: str, args: dict[str, Any],
        *, session: str | None = None,
    ) -> tuple[ActionOutcome | None, dict[str, Any], dict[str, int], list[dict[str, Any]]]:
        """Run the tool's string arguments through the content gate (outbound).

        Returns ``(denial | None, args, redaction, findings)``. Block -> the call
        never happens. Strip -> the offending value is redacted **in the
        arguments the caller must then use**, so the tool is invoked with the
        placeholder, not the secret. Scanning is per-string-field, which keeps
        each placeholder local to the field it came from (the same choice the
        reverse-proxy DLP makes for prompts). Nested dicts/lists are walked;
        non-strings carry no payload.
        """
        redaction: dict[str, int] = {}
        findings: list[dict[str, Any]] = []
        if self._gate is None:
            return None, args, redaction, findings

        ctx = ScanContext(actor=actor, direction="outbound", target=target,
                          content_type="text/plain")

        def walk(value: Any) -> Any:
            if isinstance(value, str):
                if not value:
                    return value
                result = self._gate.scan_text(value, ctx)
                if result.blocked:
                    raise _ArgBlocked(result)
                if result.verdict == "strip":
                    for cls, n in (result.redaction or {}).items():
                        redaction[cls] = redaction.get(cls, 0) + n
                    findings.extend(result.findings)
                    return result.text
                if result.findings:
                    findings.extend(result.findings)
                return value
            if isinstance(value, dict):
                return {k: walk(v) for k, v in value.items()}
            if isinstance(value, list):
                return [walk(v) for v in value]
            return value  # ints/bools/None carry no payload

        try:
            redacted = walk(args)
        except _ArgBlocked as blocked:
            result = blocked.result
            decision = Decision.block(
                result.block_reason or BlockReason.CONTENT_BLOCKED,
                [finding("tool_args", "tool.arg_exfiltration", "high",
                         owasp="ASI03", mitre="T1041")] + result.findings,
            )
            return (self._deny(actor, target, decision, session=session),
                    args, redaction, findings)

        return None, redacted, redaction, findings

    def resume(self, request_id: str, actor: str, tool: str,
               *, session_id: str = "default") -> ActionOutcome:
        """Re-evaluate a held call after an operator resolved its approval."""
        decision = self._hitl.decision(request_id)
        target = f"tool:{tool}"
        verdict = "allow" if decision.allowed else "block"
        self._record(actor=actor, action="mcp_tool_call", target=target,
                     verdict=verdict, block_reason=decision.block_reason,
                     findings=decision.findings, session=session_id)
        return ActionOutcome(decision=decision, hitl_request_id=request_id)

    def scan_result(
        self, text: str, *, actor: str = "", tool: str = "", session_id: str = "default",
    ) -> GateResult:
        """Scan a tool result (bidirectional). Taints the session on a hostile
        result so subsequent protected calls escalate. Returns the GateResult
        (blocked/strip/allow); the caller withholds a blocked result."""
        target = f"tool:{tool}:result"
        if self._gate is None:
            return GateResult(verdict="allow", text=text)
        result = self._gate.scan_text(
            text, ScanContext(actor=actor, direction="inbound", target=target,
                              content_type="text/plain"))
        if result.blocked:
            self._taint.mark(session_id, TaintSource.INJECTION_DETECTED)
            self._record(actor=actor, action="mcp_tool_result", target=target,
                         verdict="block", block_reason=result.block_reason,
                         findings=result.findings, session=session_id)
        elif result.verdict in ("strip", "warn"):
            self._taint.mark(session_id, TaintSource.UNPINNED_TOOL_RESULT)
            self._record(actor=actor, action="mcp_tool_result", target=target,
                         verdict=result.verdict, findings=result.findings,
                         redaction=result.redaction or None, session=session_id)
        return result

    def _deny(self, actor: str, target: str, decision: Decision,
              *, session: str | None = None) -> ActionOutcome:
        self._record(actor=actor or "anonymous", action="mcp_tool_call", target=target,
                     verdict="block", block_reason=decision.block_reason,
                     findings=decision.findings, session=session)
        return ActionOutcome(decision=decision)


__all__ = ["ActionGate", "ActionOutcome"]
