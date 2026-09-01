"""detect-secrets adapter — an external engine behind the Scanner seam.

The adapter puts Yelp's detect-secrets behind the same ``scan()`` surface as
the baseline scanners: purely additive, engine semantics untouched, and —
proven here — a crashing or hanging adapter blocks, it never weakens a
verdict. Receipts carry redaction class counts only, never the matched
plaintext, and the adapter owns its detector instances so concurrent scans
share no global state.
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


# -- global-state and coverage hazards ----------------------------------------------

def test_scan_never_touches_the_process_global_settings(monkeypatch):
    """detect-secrets' transient_settings mutates a process-global singleton;
    two concurrent scans through it race, and the loser scans with zero
    plugins — a silent fail-open. The adapter must hold its own detector
    instances and never go near the global."""
    import detect_secrets.settings as ds_settings

    def forbidden(*a, **k):
        raise AssertionError("adapter reached for process-global settings")

    scanner = DetectSecretsScanner()  # built before the patch: plugins are owned
    monkeypatch.setattr(ds_settings, "transient_settings", forbidden)
    monkeypatch.setattr(ds_settings, "get_settings", forbidden)
    findings = scanner.scan(f"aws_access_key_id = {AWS_KEY}\n", CTX)
    assert findings and findings[0].redaction_class


def test_concurrent_scans_all_find_the_secret():
    import threading

    scanner = DetectSecretsScanner()
    text = f"token={SLACK_TOKEN}\n"
    misses: list[int] = []

    def worker():
        for _ in range(30):
            if not scanner.scan(text, CTX):
                misses.append(1)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not misses, f"{len(misses)} concurrent scans missed a planted secret"


def test_private_key_material_blocks_not_header_strips():
    """PrivateKeyDetector reports only the armor header; stripping that would
    deliver the entire key body under a 'strip' verdict. Key material blocks."""
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA7bq0BK9V8vHhlG9c2fBqcrzvR5V0dEXAMPLEKEYBODY0000\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    result = _gate(DetectSecretsScanner()).scan_text(f"debug dump:\n{pem}", CTX)
    assert result.blocked, (
        f"a private key passed with verdict {result.verdict!r}: "
        "the body would be delivered with only the header redacted"
    )


def test_a_secret_repeated_on_one_line_is_fully_redacted():
    sendgrid = "SG." + "a" * 22 + "." + "b" * 43
    result = _gate(DetectSecretsScanner()).scan_text(
        f"key {sendgrid} backup {sendgrid}\n", CTX)
    if result.verdict == "strip":
        assert sendgrid not in result.text, (
            "the second occurrence survived redaction"
        )
    else:
        assert result.blocked


# -- configuration seam --------------------------------------------------------------

def test_enabling_without_the_library_refuses_at_construction(monkeypatch):
    import sys

    from al_core.config import load_settings
    from al_core.detect.scanners import default_scanners

    # Make any fresh `import detect_secrets` fail, as on a plain install.
    for mod in list(sys.modules):
        if mod == "detect_secrets" or mod.startswith("detect_secrets."):
            monkeypatch.setitem(sys.modules, mod, None)

    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as d:
        cfg = Path(d) / "cfg.yaml"
        cfg.write_text(
            "mode: balanced\nscanner:\n  detect_secrets:\n    enabled: true\n",
            encoding="utf-8",
        )
        with pytest.raises(ImportError):
            default_scanners(load_settings(cfg))

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
