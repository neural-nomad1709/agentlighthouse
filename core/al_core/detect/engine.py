"""L2×L3 content gate — normalize, scan every variant, resolve one verdict.

The engine is the *only* place scanner results turn into a decision, and it
is deliberately paranoid:

* every scanner call is wrapped — an exception becomes a **block**
  (``SCANNER_FAILED``, critical), never a skip;
* a cooperative deadline runs between scanner calls — overruns become a
  **block** (``SCANNER_TIMEOUT``); the async wrapper adds a hard wall-clock
  timeout for scanners that hang inside a single call;
* verdict precedence is ``block > strip > warn > ask > allow`` and unknown
  action strings rank as block (a broken adapter cannot weaken the verdict);
* a scanner block **wins over any allowlist** by construction: the gateway
  consults the gate after its own allow decision and applies the stronger
  verdict;
* ``strip`` findings are redacted with typed placeholders on the original
  text; a strip-worthy rule whose hits are visible *only* on decoded/folded
  variants escalates to block — content hiding a secret behind an encoding
  is exfiltration-shaped, and decoded text cannot be redacted back into the
  original faithfully;
* audit mode never enforces (that is its contract) but records everything:
  the result carries ``enforced=False`` and the full findings for the
  receipt. The one exception is a broken pipeline — a gate that cannot scan
  cannot claim to observe, so engine failures block even in audit mode.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Sequence

from ..gateway.decision import BlockReason
from ..normalize import normalize_variants
from .base import GateResult, ScanContext, ScanFinding, Scanner, action_rank, severity_rank

log = logging.getLogger("al.detect")

_REDACT_FMT = "[REDACTED:{cls}]"
_KNOWN_ACTIONS = frozenset(("allow", "ask", "warn", "strip", "block"))

#: Fallback block reason per scanner name when a blocking finding does not
#: carry its own. Kept here (not in adapters) so the vocabulary stays closed.
_SCANNER_REASONS = {
    "injection": BlockReason.INJECTION_BLOCKED,
    "secrets": BlockReason.SECRET_BLOCKED,
    "bip39": BlockReason.SEED_PHRASE_BLOCKED,
    "pii": BlockReason.PII_BLOCKED,
    "entropy": BlockReason.ENTROPY_BLOCKED,
    "ssrf": BlockReason.SSRF_BLOCKED,
    "url_shape": BlockReason.INVALID_URL,
}


def _rank(f: ScanFinding) -> tuple[int, int]:
    return (action_rank(f.action), severity_rank(f.severity))


class ContentGate:
    """Run ``scanners`` over every normalization variant of a text."""

    def __init__(
        self,
        scanners: Sequence[Scanner],
        *,
        mode: str = "balanced",
        max_unwrap_depth: int = 2,
        max_variants: int = 32,
        scan_timeout_s: float = 5.0,
    ) -> None:
        self._scanners = list(scanners)
        self._mode = mode
        self._max_unwrap_depth = max_unwrap_depth
        self._max_variants = max_variants
        self._timeout_s = scan_timeout_s

    # -- sync core -----------------------------------------------------------

    def scan_text(self, text: str, ctx: ScanContext | None = None) -> GateResult:
        ctx = ctx or ScanContext()
        deadline = time.monotonic() + self._timeout_s

        variants = normalize_variants(
            text,
            max_unwrap_depth=self._max_unwrap_depth,
            max_variants=self._max_variants,
        )

        # (finding, hit_on_original_text) pairs; grouped at resolve time.
        hits: list[tuple[ScanFinding, bool]] = []
        for index, variant in enumerate(variants):
            is_original = index == 0 and variant.passes == () and variant.depth == 0
            for scanner in self._scanners:
                if time.monotonic() > deadline:
                    return self._fail_closed(
                        text, BlockReason.SCANNER_TIMEOUT, "engine.deadline_exceeded", hits,
                    )
                try:
                    found = scanner.scan(variant.text, ctx)
                except Exception:  # noqa: BLE001 — ANY scanner crash blocks
                    log.exception("scanner %r crashed — failing closed", scanner.name)
                    return self._fail_closed(
                        text, BlockReason.SCANNER_FAILED,
                        f"scanner.crash.{scanner.name}", hits,
                    )
                hits.extend((f, is_original) for f in found)
        if time.monotonic() > deadline:
            return self._fail_closed(
                text, BlockReason.SCANNER_TIMEOUT, "engine.deadline_exceeded", hits,
            )

        return self._resolve(text, hits)

    # -- async wrapper (hard wall-clock timeout for hung scanners) ------------

    async def scan(self, text: str, ctx: ScanContext | None = None) -> GateResult:
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self.scan_text, text, ctx),
                timeout=self._timeout_s + 1.0,  # cooperative deadline fires first
            )
        except asyncio.TimeoutError:
            log.error("content gate hard timeout after %.1fs — failing closed", self._timeout_s)
            return self._fail_closed(
                text, BlockReason.SCANNER_TIMEOUT, "engine.hard_timeout", [],
            )

    # -- internals -------------------------------------------------------------

    def _resolve(self, text: str, hits: list[tuple[ScanFinding, bool]]) -> GateResult:
        if not hits:
            return GateResult(verdict="allow", text=text)

        # Group by (scanner, rule_id): one receipt finding per rule, and the
        # strip-vs-block question is decided per rule, not per variant hit.
        groups: dict[tuple[str, str], list[tuple[ScanFinding, bool]]] = {}
        for f, is_orig in hits:
            groups.setdefault((f.scanner, f.rule_id), []).append((f, is_orig))

        representatives: list[ScanFinding] = []
        redactable: list[ScanFinding] = []
        for group in groups.values():
            rep = max((f for f, _ in group), key=_rank)
            if rep.action == "strip":
                spans = [f for f, is_orig in group
                         if f.action == "strip" and is_orig and f.span is not None]
                if spans:
                    redactable.extend(spans)
                else:
                    # Visible only behind an encoding: harden to block.
                    rep = ScanFinding(
                        scanner=rep.scanner, rule_id=rep.rule_id, severity=rep.severity,
                        action="block", owasp=rep.owasp, mitre=rep.mitre,
                        block_reason=rep.block_reason,
                    )
            elif rep.action not in _KNOWN_ACTIONS:
                # Ambiguous verdict from a misbehaving adapter -> deny.
                rep = ScanFinding(
                    scanner=rep.scanner, rule_id=rep.rule_id, severity=rep.severity,
                    action="block", owasp=rep.owasp, mitre=rep.mitre,
                    block_reason=rep.block_reason,
                )
            representatives.append(rep)

        top = max(representatives, key=_rank)
        verdict = top.action
        receipt_findings = [f.to_receipt() for f in representatives]

        # Audit mode observes: verdict downgrades to warn, content flows
        # unmodified, findings + enforced=False still land in the receipt.
        if self._mode == "audit" and verdict in ("strip", "block", "ask"):
            return GateResult(
                verdict="warn", text=text, findings=receipt_findings, enforced=False,
            )

        # Strict mode escalates warn -> block (rollout ladder audit->balanced->strict).
        if self._mode == "strict" and verdict == "warn":
            verdict = "block"

        if verdict == "block":
            reason = top.block_reason or _SCANNER_REASONS.get(
                top.scanner, BlockReason.CONTENT_BLOCKED
            )
            return GateResult(
                verdict="block", text=text, block_reason=reason, findings=receipt_findings,
            )

        if verdict == "strip":
            redacted, counts = _apply_redaction(text, redactable)
            return GateResult(
                verdict="strip", text=redacted, findings=receipt_findings, redaction=counts,
            )

        if verdict == "ask":
            # No HITL path until Phase 3 — surface as ask, gateway denies with
            # a precise, retryable-when-approved reason.
            return GateResult(
                verdict="ask", text=text,
                block_reason=BlockReason.APPROVAL_REQUIRED, findings=receipt_findings,
            )

        return GateResult(verdict=verdict, text=text, findings=receipt_findings)

    def _fail_closed(
        self,
        text: str,
        reason: str,
        rule_id: str,
        partial: list[tuple[ScanFinding, bool]],
    ) -> GateResult:
        failure = ScanFinding(
            scanner="engine", rule_id=rule_id, severity="critical", action="block",
        )
        seen: set[tuple[str, str]] = set()
        found: list[dict] = []
        for f, _ in [*partial, (failure, True)]:
            key = (f.scanner, f.rule_id)
            if key not in seen:
                seen.add(key)
                found.append(f.to_receipt())
        if self._mode == "audit":
            log.critical("content gate failure in audit mode — blocking anyway")
        return GateResult(verdict="block", text=text, block_reason=reason, findings=found)


def _apply_redaction(
    text: str, strips: list[ScanFinding]
) -> tuple[str, dict[str, int]]:
    """Replace strip spans with typed placeholders; return (text, class counts).

    Overlapping spans merge into one placeholder carrying the first class —
    counts still tally every finding (the receipt reports what was found,
    the text just cannot show two placeholders in one place).
    """
    counts: dict[str, int] = {}
    spans: list[tuple[int, int, str]] = []
    for f in strips:
        cls = f.redaction_class or f.rule_id
        counts[cls] = counts.get(cls, 0) + 1
        start, end = f.span  # type: ignore[misc] — caller guarantees span
        start, end = max(0, start), min(len(text), end)
        if start < end:
            spans.append((start, end, cls))

    merged: list[tuple[int, int, str]] = []
    for start, end, cls in sorted(spans):
        if merged and start <= merged[-1][1]:
            last = merged[-1]
            merged[-1] = (last[0], max(last[1], end), last[2])
        else:
            merged.append((start, end, cls))

    out = text
    for start, end, cls in reversed(merged):
        out = out[:start] + _REDACT_FMT.format(cls=cls) + out[end:]
    return out, counts


__all__ = ["ContentGate"]
