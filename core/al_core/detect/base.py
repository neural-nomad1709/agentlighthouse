"""L3 scanner interface — uniform, swappable, fail-closed by construction.

Every detector (injection, secrets, PII, SSRF, entropy, BIP-39, …) implements
the same tiny surface: ``scan(text, ctx) -> list[ScanFinding]``. Engines and
adapters can be swapped (LLM Guard, Presidio, detect-secrets) without touching
the pipeline, and the pipeline treats *any* scanner misbehaviour — exception,
timeout, unknown action string — as a block (the fail-closed matrix).

Findings carry their own proposed ``action`` (verdict vocabulary from
spec/receipt-v1: ``block > strip > warn > ask > allow``) plus, for ``strip``,
the span to redact and a typed redaction class. Findings never carry the
matched plaintext — receipts record redaction *class counts only*.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

Action = Literal["allow", "ask", "warn", "strip", "block"]

#: Verdict precedence (receipt-v1 §2). Unknown actions rank as block — an
#: adapter that emits garbage must never weaken the verdict (fail-closed).
_PRECEDENCE: dict[str, int] = {"allow": 0, "ask": 1, "warn": 2, "strip": 3, "block": 4}


def action_rank(action: str) -> int:
    return _PRECEDENCE.get(action, _PRECEDENCE["block"])


_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity, _SEVERITY_RANK["critical"])


@dataclass(frozen=True)
class ScanContext:
    """What the scanners are looking at (never *why* — no policy in here)."""

    actor: str = "anonymous"
    direction: Literal["inbound", "outbound"] = "inbound"
    target: str = ""
    content_type: str = "text/plain"


@dataclass(frozen=True)
class ScanFinding:
    """One detector hit on one scan variant.

    ``span`` indexes into the *text that was scanned* (a normalization
    variant). The engine only applies redaction for spans found on the
    original text; a strip-worthy hit that is only visible on a derived
    variant escalates to block instead — content hiding a secret behind an
    encoding is exfiltration-shaped, and rewriting decoded text back into
    the original is not possible faithfully.
    """

    scanner: str
    rule_id: str
    severity: str = "high"
    action: str = "block"
    owasp: str | None = None
    mitre: str | None = None
    span: tuple[int, int] | None = None
    redaction_class: str | None = None
    block_reason: str | None = None  # fixed vocabulary; engine picks the winner

    def to_receipt(self) -> dict[str, Any]:
        """Receipt-shaped finding (spec fields only; never plaintext)."""
        f: dict[str, Any] = {
            "scanner": self.scanner,
            "rule_id": self.rule_id,
            "severity": self.severity,
        }
        if self.owasp is not None:
            f["owasp"] = self.owasp
        if self.mitre is not None:
            f["mitre"] = self.mitre
        return f


@runtime_checkable
class Scanner(Protocol):
    """The uniform detector surface. Implementations must be thread-safe and
    side-effect free; state (budgets, rate windows) lives behind the same
    interface but keys off ``ScanContext``, never mutates the text."""

    name: str

    def scan(self, text: str, ctx: ScanContext) -> list[ScanFinding]: ...


@dataclass
class GateResult:
    """Outcome of one content-gate evaluation.

    ``text`` is the deliverable content — the original, with typed
    placeholders substituted when the verdict is ``strip``. ``findings`` are
    receipt-shaped dicts ready for ``Ledger.record``; ``redaction`` is the
    class -> count map for the receipt (counts only, never plaintext).
    ``enforced`` is False when audit mode observed a would-be block/strip and
    let the content flow — the receipt still records what was found.
    """

    verdict: str
    text: str
    block_reason: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    redaction: dict[str, int] = field(default_factory=dict)
    enforced: bool = True

    @property
    def blocked(self) -> bool:
        return self.verdict == "block"


__all__ = [
    "Action",
    "GateResult",
    "ScanContext",
    "ScanFinding",
    "Scanner",
    "action_rank",
    "severity_rank",
]
