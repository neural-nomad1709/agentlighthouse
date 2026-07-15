"""failclosed_scanner_test — scanner crash/timeout/ambiguity must DENY.

The fail-closed proof matrix: these tests prove *denial*, not
normal blocking. A detection pipeline that fails open is worse than none —
operators believe they are protected.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from al_core.detect import ContentGate, ScanContext, ScanFinding
from al_core.gateway.decision import BlockReason


class CrashScanner:
    name = "crashy"

    def scan(self, text: str, ctx: ScanContext) -> list[ScanFinding]:
        raise RuntimeError("adapter exploded")


@dataclass
class SlowScanner:
    name: str = "slow"
    sleep_s: float = 0.15

    def scan(self, text: str, ctx: ScanContext) -> list[ScanFinding]:
        time.sleep(self.sleep_s)
        return []


class AmbiguousScanner:
    """Emits a high-severity finding with a nonsense action string."""

    name = "weird"

    def scan(self, text: str, ctx: ScanContext) -> list[ScanFinding]:
        return [ScanFinding(scanner=self.name, rule_id="weird.r",
                            severity="high", action="proceed-maybe")]


class OkScanner:
    name = "ok"

    def scan(self, text: str, ctx: ScanContext) -> list[ScanFinding]:
        return [ScanFinding(scanner=self.name, rule_id="ok.warn",
                            severity="low", action="warn")]


def test_scanner_crash_blocks() -> None:
    r = ContentGate([CrashScanner()]).scan_text("any text")
    assert r.blocked and r.block_reason == BlockReason.SCANNER_FAILED
    assert any(f["scanner"] == "engine" and f["severity"] == "critical"
               for f in r.findings)


def test_crash_blocks_even_with_healthy_scanners() -> None:
    r = ContentGate([OkScanner(), CrashScanner()]).scan_text("any text")
    assert r.blocked and r.block_reason == BlockReason.SCANNER_FAILED


def test_scanner_crash_blocks_even_in_audit_mode() -> None:
    # audit mode observes findings; it does NOT excuse a broken pipeline
    r = ContentGate([CrashScanner()], mode="audit").scan_text("any")
    assert r.blocked and r.block_reason == BlockReason.SCANNER_FAILED


def test_cooperative_timeout_blocks() -> None:
    r = ContentGate([SlowScanner(sleep_s=0.2)], scan_timeout_s=0.05).scan_text("hi")
    assert r.blocked and r.block_reason == BlockReason.SCANNER_TIMEOUT


def test_timeout_keeps_partial_findings_in_receipt() -> None:
    r = ContentGate(
        [OkScanner(), SlowScanner(sleep_s=0.2)], scan_timeout_s=0.05
    ).scan_text("hello")
    assert r.blocked and r.block_reason == BlockReason.SCANNER_TIMEOUT
    assert any(f["scanner"] == "ok" for f in r.findings)
    assert any(f["scanner"] == "engine" for f in r.findings)


def test_hard_timeout_via_async_wrapper() -> None:
    # a scanner hanging INSIDE one call escapes the cooperative deadline;
    # the async wrapper's wall-clock timeout must still deny
    g = ContentGate([SlowScanner(sleep_s=1.5)], scan_timeout_s=0.2)
    r = asyncio.run(g.scan("hi"))
    assert r.blocked and r.block_reason == BlockReason.SCANNER_TIMEOUT


def test_ambiguous_high_severity_verdict_denies() -> None:
    r = ContentGate([AmbiguousScanner()]).scan_text("whatever")
    assert r.blocked  # unknown action ranks as block — fail closed


def test_ambiguous_action_never_weakens_real_verdict() -> None:
    r = ContentGate([AmbiguousScanner(), OkScanner()]).scan_text("x")
    assert r.blocked
