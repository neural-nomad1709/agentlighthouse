"""Receipt chain + standalone verifier (receipt_test — Phase 0 acceptance)."""

from __future__ import annotations

import copy
import json
import subprocess
import sys

import pytest

from al_core.keys import public_key_hex
from al_verify.verify import (
    ChainBroken,
    RecordHashMismatch,
    SignatureInvalid,
    verify_chain,
    verify_receipt,
)


def _chain(signer):
    r0 = signer.record(
        actor="spiffe://acme/agent/claude-code",
        action="mcp_tool_call",
        target="tool:send_email",
        verdict="block",
        findings=[{"scanner": "tool_policy", "rule_id": "policy.default_deny",
                   "severity": "high", "owasp": "ASI03", "mitre": "T1078"}],
        block_reason="TOOL_NOT_ALLOWED",
        ts="2026-07-10T12:00:00.000Z",
    )
    r1 = signer.record(
        actor="spiffe://acme/agent/claude-code",
        action="fetch",
        target="https://docs.python.org/3/",
        verdict="allow",
        ts="2026-07-10T12:00:01.000Z",
    )
    return r0, r1


def test_valid_chain_verifies(signer, public_key):
    r0, r1 = _chain(signer)
    assert verify_chain([r0, r1], public_key) == 2


def test_genesis_prev_hash(signer):
    r0, _ = _chain(signer)
    assert r0["prev_hash"] == "sha256:" + "0" * 64
    assert r0["seq"] == 0


def test_field_tamper_breaks_record_hash(signer, public_key):
    r0, _ = _chain(signer)
    bad = copy.deepcopy(r0)
    bad["verdict"] = "allow"  # flip a blocked decision
    with pytest.raises(RecordHashMismatch):
        verify_receipt(bad, public_key)


def test_signature_tamper_detected(signer, public_key):
    r0, _ = _chain(signer)
    bad = copy.deepcopy(r0)
    # Recompute record_hash so only the signature is inconsistent.
    from al_verify.verify import compute_record_hash
    bad["target"] = "tool:transfer_money"
    bad["record_hash"] = compute_record_hash(bad)
    with pytest.raises(SignatureInvalid):
        verify_receipt(bad, public_key)


def test_broken_chain_link_detected(signer, public_key):
    r0, r1 = _chain(signer)
    bad1 = copy.deepcopy(r1)
    bad1["prev_hash"] = "sha256:" + "0" * 64  # point away from r0
    # record_hash/sig still valid for bad1's own content? No — prev_hash is signed.
    with pytest.raises((ChainBroken, RecordHashMismatch)):
        verify_chain([r0, bad1], public_key)


def test_noncontiguous_seq_detected(signer, public_key):
    r0, r1 = _chain(signer)
    with pytest.raises(ChainBroken):
        verify_chain([r0, r0, r1], public_key)  # seq 0,0,1


def test_redaction_is_counts_only(signer):
    r = signer.record(
        actor="spiffe://acme/agent/x", action="http_forward",
        target="https://api.example.com", verdict="strip",
        redaction={"aws-access-key": 2}, ts="2026-07-10T12:00:02.000Z",
    )
    assert r["redaction"] == {"aws-access-key": 2}
    assert "AKIA" not in json.dumps(r)  # never plaintext


def test_alverify_runs_without_al_core(tmp_path, signer, signing_key):
    """The standalone verifier must import and run without al_core present."""
    # 1. al_verify imports cleanly in a fresh interpreter with no al_core.
    probe = subprocess.run(
        [sys.executable, "-c", "import al_verify, sys; assert 'al_core' not in sys.modules; print('ok')"],
        capture_output=True, text=True,
    )
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.strip() == "ok"

    # 2. The al-verify CLI verifies a real core-produced ledger.
    r0, r1 = _chain(signer)
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("\n".join(json.dumps(r) for r in (r0, r1)) + "\n", encoding="utf-8")
    pub = tmp_path / "pub.hex"
    pub.write_text(public_key_hex(signing_key.public_key()), encoding="utf-8")

    ok = subprocess.run(
        [sys.executable, "-m", "al_verify.cli", str(ledger), "--pubkey", str(pub)],
        capture_output=True, text=True,
    )
    assert ok.returncode == 0, ok.stderr

    # 3. Tampering makes the CLI fail (non-zero exit).
    tampered = ledger.read_text().replace("TOOL_NOT_ALLOWED", "TOOL_ALLOWED")
    ledger.write_text(tampered, encoding="utf-8")
    bad = subprocess.run(
        [sys.executable, "-m", "al_verify.cli", str(ledger), "--pubkey", str(pub)],
        capture_output=True, text=True,
    )
    assert bad.returncode == 1, bad.stdout + bad.stderr
