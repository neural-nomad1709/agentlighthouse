"""Gateway decisions + the fixed machine-readable ``block_reason`` vocabulary.

Denials must be **agent-legible** (invariant: explainable intercepts). Every
non-allow verdict carries one of these fixed reasons so an agent — or a human
reading a receipt — can tell exactly why it was stopped and whether a retry
could ever succeed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from .dnspin import Pin


class BlockReason:
    """Fixed vocabulary (spec: receipt-v1 ``block_reason``). Values are stable."""

    NO_IDENTITY = "NO_IDENTITY"                      # authenticate and retry
    INVALID_VIRTUAL_KEY = "INVALID_VIRTUAL_KEY"      # obtain a valid key
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"              # retry after budget reset
    HOST_NOT_ALLOWED = "HOST_NOT_ALLOWED"            # not retryable without policy change
    PORT_NOT_ALLOWED = "PORT_NOT_ALLOWED"            # not retryable without policy change
    SCHEME_NOT_ALLOWED = "SCHEME_NOT_ALLOWED"        # use http/https
    URL_TOO_LONG = "URL_TOO_LONG"                    # shorten the URL
    INVALID_URL = "INVALID_URL"                      # malformed / userinfo smuggling
    SSRF_BLOCKED = "SSRF_BLOCKED"                    # never retryable
    DNS_REBIND_BLOCKED = "DNS_REBIND_BLOCKED"        # never retryable
    DNS_RESOLUTION_FAILED = "DNS_RESOLUTION_FAILED"  # transient; retry may succeed
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"        # use a supported method
    TOO_MANY_REDIRECTS = "TOO_MANY_REDIRECTS"        # destination redirect-chains too far
    SIZE_EXCEEDED = "SIZE_EXCEEDED"                  # response larger than fetch_max_bytes
    UPSTREAM_NOT_CONFIGURED = "UPSTREAM_NOT_CONFIGURED"  # operator action required
    EGRESS_BYPASS_DETECTED = "EGRESS_BYPASS_DETECTED"    # deployment broken; refuse to run
    # -- Phase 2: content gate (L2/L3) --------------------------------------
    INJECTION_BLOCKED = "INJECTION_BLOCKED"          # never retryable as-is
    SECRET_BLOCKED = "SECRET_BLOCKED"                # remove the credential and retry
    SEED_PHRASE_BLOCKED = "SEED_PHRASE_BLOCKED"      # BIP-39 wallet material; never retryable
    PII_BLOCKED = "PII_BLOCKED"                      # strict-mode PII denial
    ENTROPY_BLOCKED = "ENTROPY_BLOCKED"              # encoded-blob/DNS-tunnel shape
    CONTENT_BLOCKED = "CONTENT_BLOCKED"              # generic content-gate denial
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"      # retry after the window passes
    DATA_BUDGET_EXCEEDED = "DATA_BUDGET_EXCEEDED"    # retry after budget reset
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"          # ask-verdict without a HITL path (pre-P3)
    SCANNER_FAILED = "SCANNER_FAILED"                # fail-closed: detector crashed
    SCANNER_TIMEOUT = "SCANNER_TIMEOUT"              # fail-closed: detector overran deadline
    # -- Phase 3: action gate (L4 tool policy + MCP) ------------------------
    TOOL_NOT_ALLOWED = "TOOL_NOT_ALLOWED"            # default-deny: not in this identity's allow list
    TOOL_DENIED = "TOOL_DENIED"                      # explicit deny rule (e.g. exec_shell)
    ARG_NOT_ALLOWED = "ARG_NOT_ALLOWED"              # argument constraint violated (host/path/value)
    TOOL_RATE_EXCEEDED = "TOOL_RATE_EXCEEDED"        # per-identity tool-call budget exhausted
    HITL_REQUIRED = "HITL_REQUIRED"                  # irreversible verb awaiting human approval
    HITL_DENIED = "HITL_DENIED"                      # approval denied or timed out -> deny
    TOOL_POISONED = "TOOL_POISONED"                  # tool description carries an injection payload
    TOOL_DESCRIPTOR_DRIFT = "TOOL_DESCRIPTOR_DRIFT"  # pinned descriptor changed (rug-pull)
    TOOL_CHAIN_DETECTED = "TOOL_CHAIN_DETECTED"      # recon->stage->exfil sequence flagged
    NO_IDENTITY_TOOL = "NO_IDENTITY_TOOL"            # tool call without a registered identity
    # -- Phase 4: memory guard (L5) ------------------------------------------
    MEMORY_POISON_BLOCKED = "MEMORY_POISON_BLOCKED"  # poisoned entry blocked (+ quarantined)
    PROTECTED_KEY_TAMPERED = "PROTECTED_KEY_TAMPERED"  # integrity baseline mismatch
    MEMORY_KEY_PROTECTED = "MEMORY_KEY_PROTECTED"    # identity may not write a protected key
    MEMORY_SIZE_EXCEEDED = "MEMORY_SIZE_EXCEEDED"    # value over memory.max_value_bytes
    # -- Phase 5: evidence & control (L6) --------------------------------------
    KILLSWITCH_ENGAGED = "KILLSWITCH_ENGAGED"        # full deny-all until disengaged
    RESULT_BLOCKED = "RESULT_BLOCKED"                # tool result withheld by content gate
    # -- Phase 7: A2A + learning loop ------------------------------------------
    A2A_CARD_DRIFT = "A2A_CARD_DRIFT"                # pinned Agent Card changed (ASI07)
    A2A_CARD_POISONED = "A2A_CARD_POISONED"          # Agent Card carries an injection payload
    A2A_SESSION_SMUGGLED = "A2A_SESSION_SMUGGLED"    # session id reused across a different peer
    A2A_MESSAGE_BLOCKED = "A2A_MESSAGE_BLOCKED"      # inter-agent payload blocked by the content gate
    RULE_BUNDLE_UNSIGNED = "RULE_BUNDLE_UNSIGNED"    # learned rules refused: bad/missing signature
    # -- Skill guard: agent instruction files (SKILL.md / CLAUDE.md / rules) --
    SKILL_POISONED = "SKILL_POISONED"                # instruction file carries an injection payload
    SKILL_DRIFT = "SKILL_DRIFT"                      # pinned instruction file changed (rug-pull)
    SKILL_SIZE_EXCEEDED = "SKILL_SIZE_EXCEEDED"      # instruction file over skills.max_bytes


@dataclass
class Decision:
    """Outcome of one gateway policy evaluation.

    ``findings`` entries are plain dicts shaped like ``receipt.Finding``
    (scanner / rule_id / severity / owasp / mitre) so they drop straight into
    ``Ledger.record(findings=...)``.
    """

    verdict: str  # "allow" | "block"  (Phase 2 adds strip/warn/ask)
    block_reason: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    pin: "Pin | None" = None  # populated on allow when DNS pinning ran

    @property
    def allowed(self) -> bool:
        return self.verdict == "allow"

    @staticmethod
    def allow(pin: "Pin | None" = None) -> "Decision":
        return Decision(verdict="allow", pin=pin)

    @staticmethod
    def block(reason: str, findings: list[dict[str, Any]] | None = None) -> "Decision":
        return Decision(verdict="block", block_reason=reason, findings=findings or [])


def finding(
    scanner: str,
    rule_id: str,
    severity: str = "high",
    *,
    owasp: str | None = None,
    mitre: str | None = None,
) -> dict[str, Any]:
    """Build one receipt-shaped finding dict (drops None fields)."""
    f: dict[str, Any] = {"scanner": scanner, "rule_id": rule_id, "severity": severity}
    if owasp is not None:
        f["owasp"] = owasp
    if mitre is not None:
        f["mitre"] = mitre
    return f


__all__ = ["BlockReason", "Decision", "finding"]
