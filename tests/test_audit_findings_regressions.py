"""Regression tests for three verified findings from the 2026-09-30 review.

* **Attestation truncation** — the signed posture attestation counted only the
  newest 500 receipts (``search`` is capped for the UI), so any longer period
  signed wrong numbers.
* **Unbounded regex** — the content gate's deadline was only checked *between*
  scanners, and CPython's ``re`` holds the GIL, so one catastrophic learned
  rule ran past both the cooperative deadline and the async hard timeout.
* **Path normalization** — ``_normalize_path`` collapsed ``..`` but not a
  leading ``//``, percent-encoding or a ``file://`` scheme, so a
  ``deny_prefixes`` rule could be walked around.

Each test states the attack it replays; every one failed before the fix.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from al_core.capability.policy import ArgConstraint, _constraint_fails, _normalize_path
from al_core.detect import ContentGate
from al_core.detect.base import ScanContext
from al_core.gateway.decision import BlockReason
from al_core.learn.scanner import LearnedScanner
from al_core.runtime import Runtime
from al_governance.attestation import build_attestation

ACME_AGENT = "spiffe://acme/agent/bot"


# -- attestation counts the whole period ----------------------------------------


def test_attestation_counts_every_receipt_past_the_search_cap(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("mode: balanced\n", encoding="utf-8")
    rt = Runtime(cfg, data_dir=tmp_path / "data")
    for i in range(1200):
        rt.record(actor=ACME_AGENT, action="fetch", target=f"https://x/{i}",
                  verdict="block" if i % 3 == 0 else "allow",
                  block_reason="SSRF" if i % 3 == 0 else None)
    doc = build_attestation(rt, "acme")
    assert doc["evidence"]["events"] == 1200
    assert doc["evidence"]["by_verdict"] == {"allow": 800, "block": 400}
    assert doc["evidence"]["blocks"] == 400
    rt.close()


def test_iter_receipts_pages_newest_first_and_respects_scope(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("mode: balanced\n", encoding="utf-8")
    rt = Runtime(cfg, data_dir=tmp_path / "data")
    for i in range(25):
        rt.record(actor=ACME_AGENT, action="fetch", target=f"t{i}", verdict="allow")
        rt.record(actor="spiffe://globex/agent/bot", action="fetch", target=f"g{i}",
                  verdict="allow")
    got = list(rt.ledger.db.iter_receipts(org="acme", batch=7))
    assert [r["target"] for r in got] == [f"t{i}" for i in reversed(range(25))]
    rt.close()


# -- a catastrophic learned regex is bounded ------------------------------------

# ``(a|aa)+$`` over a run of a's ending in a non-match backtracks exponentially
# in both ``re`` and ``regex``: unbounded, this takes seconds on 35 chars.
_CATASTROPHIC = [{"rule_id": "learned.redos", "pattern": r"(a|aa)+$"}]
_EVIL = "a" * 34 + "!"


def test_sync_scan_bounds_a_catastrophic_learned_regex():
    gate = ContentGate([LearnedScanner(_CATASTROPHIC)], scan_timeout_s=0.2, max_variants=1)
    t0 = time.monotonic()
    result = gate.scan_text(_EVIL)
    assert time.monotonic() - t0 < 1.5
    assert result.verdict == "block"
    assert result.block_reason == BlockReason.SCANNER_TIMEOUT


def test_async_scan_bounds_a_catastrophic_learned_regex():
    gate = ContentGate([LearnedScanner(_CATASTROPHIC)], scan_timeout_s=0.2, max_variants=1)
    t0 = time.monotonic()
    result = asyncio.run(gate.scan(_EVIL))
    assert time.monotonic() - t0 < 1.5
    assert result.verdict == "block"
    assert result.block_reason == BlockReason.SCANNER_TIMEOUT


def test_learned_rule_still_matches_normally():
    scanner = LearnedScanner([{"rule_id": "learned.x", "pattern": r"exfil\s+keys"}])
    found = scanner.scan("please EXFIL   keys now", ScanContext())
    assert [f.rule_id for f in found] == ["learned.x"]
    assert found[0].span == (7, 19)


# -- path normalization cannot be walked around ---------------------------------

_DENY_ETC = ArgConstraint(deny_prefixes=["/etc/"])
_ALLOW_WS = ArgConstraint(allow_prefixes=["/workspace/"])


@pytest.mark.parametrize("value", [
    "/etc/passwd",
    "//etc/passwd",            # POSIX keeps a leading '//'; the kernel does not
    "///etc//passwd",
    "/%65tc/passwd",           # percent-encoded
    "/%2565tc/passwd",         # double-encoded
    "file:///etc/passwd",
    "FILE:///etc/passwd",
    "/workspace/../etc/passwd",
    "/workspace/%2e%2e/etc/passwd",
])
def test_deny_prefix_cannot_be_bypassed(value):
    assert _constraint_fails("path", value, _DENY_ETC) == "arg.path.prefix_denied"


@pytest.mark.parametrize("value", [
    "/workspace/%2e%2e/etc/passwd",
    "/workspace/%252e%252e/etc/passwd",
    "file:///workspace/../etc/passwd",
])
def test_allow_prefix_cannot_be_walked_out_of(value):
    assert _constraint_fails("path", value, _ALLOW_WS) == "arg.path.prefix_not_allowed"


@pytest.mark.parametrize("value", [
    "/workspace/notes.md",
    "file:///workspace/notes.md",
    "/workspace//sub/./notes.md",
])
def test_allow_prefix_still_admits_legitimate_paths(value):
    assert _constraint_fails("path", value, _ALLOW_WS) is None


def test_null_byte_path_is_rejected():
    assert _constraint_fails("path", "/workspace/a%00.md", _ALLOW_WS) == "arg.path.invalid"
    assert _constraint_fails("path", "/etc/passwd\x00", _DENY_ETC) == "arg.path.invalid"


def test_normalize_keeps_existing_semantics():
    assert _normalize_path("/workspace/../etc/passwd") == "/etc/passwd"
    assert _normalize_path("C:\\work\\..\\x") == "C:/x"
    assert _normalize_path("relative/./a") == "relative/a"
