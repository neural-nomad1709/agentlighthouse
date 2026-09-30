"""LearnedScanner — approved rules enter detection through the front door.

The Phase-2 ``Scanner`` protocol was built so engines could be swapped without
touching the pipeline. Learned rules use that same seam: they are just another
scanner. That means a learned rule inherits every guarantee the pipeline
already gives — it runs over every normalization variant (so an evasion-folded
version of the attack is caught too), its verdict resolves by the same
precedence, and a crash in it fails closed like any other scanner.

Rules only ever come from a **verified** bundle (``bundle.load_bundle``), so
this class never sees an unsigned rule.

Signed is not the same as safe to run: a human-approved pattern can still
backtrack catastrophically on attacker-chosen text. Rules are compiled with
the ``regex`` engine so every match is bounded by the gate's deadline (and
releases the GIL while it runs), and an overrun raises ``TimeoutError``,
which the engine turns into a ``SCANNER_TIMEOUT`` block.
"""

from __future__ import annotations

import time
from typing import Any

import regex

from ..detect.base import ScanContext, ScanFinding


class LearnedScanner:
    name = "learned"

    def __init__(self, rules: list[dict[str, Any]]) -> None:
        self._rules: list[tuple[regex.Pattern[str], dict[str, Any]]] = []
        for rule in rules:
            try:
                pattern = regex.compile(rule["pattern"], regex.IGNORECASE)
            except regex.error:
                # A rule that cannot compile is dropped, loudly-but-safely: the
                # bundle was signed, so this is our bug, not an attack — and a
                # broken rule must not take the whole gate down.
                continue
            self._rules.append((pattern, rule))

    @property
    def rule_ids(self) -> list[str]:
        return [r["rule_id"] for _, r in self._rules]

    def scan(self, text: str, ctx: ScanContext) -> list[ScanFinding]:
        found: list[ScanFinding] = []
        for pattern, rule in self._rules:
            match = pattern.search(text, concurrent=True, timeout=_time_left(ctx))
            if match is None:
                continue
            found.append(ScanFinding(
                scanner=self.name,
                rule_id=rule["rule_id"],
                severity=rule.get("severity", "high"),
                action=rule.get("action", "block"),
                owasp=rule.get("owasp"),
                mitre=rule.get("mitre"),
                span=(match.start(), match.end()),
            ))
        return found


def _time_left(ctx: ScanContext) -> float | None:
    """Seconds until the gate's deadline (``None`` = unbounded, outside a gate)."""
    if ctx.deadline is None:
        return None
    left = ctx.deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("scan deadline already passed")
    return left


__all__ = ["LearnedScanner"]
