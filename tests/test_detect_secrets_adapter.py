"""detect-secrets adapter (AL-0.3) — the first non-regex engine behind the seam.

The `Scanner` Protocol and the fail-closed matrix have existed since Phase 2
with regex-only implementations. This adapter puts Yelp's detect-secrets
behind the same ``scan()`` surface: purely additive, engine semantics
untouched, and — proven here — a crashing or hanging adapter blocks, it never
weakens a verdict. Receipts carry redaction class counts only, never the
matched plaintext.
"""

from __future__ import annotations

import time

import pytest

from al_core.detect import ContentGate, ScanContext
from al_core.detect.detect_secrets_adapter import DetectSecretsScanner

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
SLACK_TOKEN = "xoxb-" + "123456789012-abcdefghijklmnop"

CTX = ScanContext(actor="spiffe://acme/agent/claude-code", direction="inbound",
                  target="tool:collect_logs:result")


# -- the adapter itself ------------------------------------------------------------

def test_planted_aws_key_is_found_with_class_not_plaintext():
    scanner = DetectSecretsScanner()
    findings = scanner.scan(f"config dump:\naws_access_key_id = {AWS_KEY}\n", CTX)
    assert findings, "a planted AWS key fixture produced no findings"
    hit = findings[0]
    assert hit.action in ("strip", "block")
    assert hit.redaction_class, "a secret finding must carry a typed redaction class"
    # invariant: no field of any finding carries the secret material
    for f in findings:
        for value in vars(f).values():
            assert AWS_KEY not in str(value)


def test_clean_text_produces_no_findings():
    scanner = DetectSecretsScanner()
    assert scanner.scan("Tue Aug 31 10:00:01 systemd[1]: Started nginx.\n", CTX) == []


# -- through the content gate (what P3 will actually call) --------------------------

def _gate(*scanners, timeout_s: float = 2.0) -> ContentGate:
    return ContentGate(list(scanners), scan_timeout_s=timeout_s)


def test_gate_redacts_the_secret_and_reports_counts_only():
    result = _gate(DetectSecretsScanner()).scan_text(
        f"deploy log\ntoken={SLACK_TOKEN}\ndone\n", CTX)
    assert result.verdict in ("strip", "block")
    if result.verdict == "strip":
        assert SLACK_TOKEN not in result.text, "strip must remove the secret"
        assert result.redaction and all(
            isinstance(n, int) for n in result.redaction.values())
    # receipt-shaped findings never carry plaintext
    assert SLACK_TOKEN not in str(result.findings)
    assert SLACK_TOKEN not in str(result.redaction)


def test_a_crashing_adapter_blocks():
    class CrashingAdapter(DetectSecretsScanner):
        def scan(self, text, ctx):
            raise RuntimeError("engine exploded")

    result = _gate(CrashingAdapter()).scan_text("anything at all", CTX)
    assert result.blocked
    assert result.block_reason == "SCANNER_FAILED"


def test_a_hanging_adapter_blocks():
    class HangingAdapter(DetectSecretsScanner):
        def scan(self, text, ctx):
            time.sleep(5)
            return []

    result = _gate(HangingAdapter(), timeout_s=0.2).scan_text("anything", CTX)
    assert result.blocked
    assert result.block_reason == "SCANNER_TIMEOUT"


# -- configuration seam --------------------------------------------------------------

def test_disabled_by_default_and_enabled_by_config(tmp_path):
    from al_core.config import load_settings
    from al_core.detect.scanners import default_scanners

    plain = tmp_path / "plain.yaml"
    plain.write_text("mode: balanced\n", encoding="utf-8")
    names = [type(s).__name__ for s in default_scanners(load_settings(plain))]
    assert "DetectSecretsScanner" not in names, "the adapter must be opt-in"

    enabled = tmp_path / "enabled.yaml"
    enabled.write_text(
        "mode: balanced\nscanner:\n  detect_secrets:\n    enabled: true\n",
        encoding="utf-8",
    )
    names = [type(s).__name__ for s in default_scanners(load_settings(enabled))]
    assert "DetectSecretsScanner" in names
