"""In-process tests for the `al-verify` CLI (fail-closed exit codes)."""

from __future__ import annotations

import json

import pytest

from al_core.keys import public_key_hex
from al_verify.cli import main as verify_main


@pytest.fixture
def ledger(tmp_path, signer, signing_key):
    r0 = signer.record(actor="spiffe://a/agent/b", action="mcp_tool_call",
                       target="tool:x", verdict="block", block_reason="TOOL_NOT_ALLOWED",
                       ts="2026-07-10T00:00:00.000Z")
    r1 = signer.record(actor="spiffe://a/agent/b", action="fetch",
                       target="https://e.com", verdict="allow",
                       ts="2026-07-10T00:00:01.000Z")
    jf = tmp_path / "ledger.jsonl"
    jf.write_text("\n".join(json.dumps(r) for r in (r0, r1)) + "\n", encoding="utf-8")
    single = tmp_path / "one.json"
    single.write_text(json.dumps(r0), encoding="utf-8")
    pub = tmp_path / "pub.hex"
    pub.write_text(public_key_hex(signing_key.public_key()), encoding="utf-8")
    return jf, single, pub


def test_verify_chain_ok(ledger):
    jf, _single, pub = ledger
    assert verify_main([str(jf), "--pubkey", str(pub)]) == 0


def test_verify_single_receipt_ok(ledger):
    _jf, single, pub = ledger
    assert verify_main([str(single), "--pubkey", str(pub)]) == 0


def test_verify_inline_hex_pubkey(ledger, signing_key):
    jf, _single, _pub = ledger
    hexkey = public_key_hex(signing_key.public_key())
    assert verify_main([str(jf), "--pubkey", hexkey]) == 0


def test_verify_tampered_fails(ledger):
    jf, _single, pub = ledger
    jf.write_text(jf.read_text().replace("TOOL_NOT_ALLOWED", "OK_NOW"), encoding="utf-8")
    assert verify_main([str(jf), "--pubkey", str(pub)]) == 1


def test_missing_pubkey_file_errors(ledger, tmp_path):
    jf, _single, _pub = ledger
    assert verify_main([str(jf), "--pubkey", str(tmp_path / "nope.pub")]) == 2


def test_missing_receipt_file_errors(tmp_path, ledger):
    _jf, _single, pub = ledger
    assert verify_main([str(tmp_path / "nope.jsonl"), "--pubkey", str(pub)]) == 2


def test_empty_input_errors(tmp_path, ledger):
    _jf, _single, pub = ledger
    empty = tmp_path / "empty.json"
    empty.write_text("   ", encoding="utf-8")
    assert verify_main([str(empty), "--pubkey", str(pub)]) == 2


def test_json_array_form(tmp_path, signer, signing_key):
    r0 = signer.record(actor="spiffe://a/agent/b", action="fetch",
                       target="https://e.com", verdict="allow",
                       ts="2026-07-10T00:00:00.000Z")
    arr = tmp_path / "arr.json"
    arr.write_text(json.dumps([r0]), encoding="utf-8")
    pub = tmp_path / "pub.hex"
    pub.write_text(public_key_hex(signing_key.public_key()), encoding="utf-8")
    assert verify_main([str(arr), "--pubkey", str(pub)]) == 0


# -- the other two signed kinds: attestation + rule bundle (Phase 6/7) ------------
# The verifier is the evidence-integrity code, so its malformed-input guards are
# tested, not just its happy paths: a verifier that accepts a malformed document
# is worse than no verifier.

from al_verify.verify import (
    ATTESTATION_KIND,
    RULE_BUNDLE_KIND,
    MalformedReceipt,
    verify_attestation,
    verify_rule_bundle,
)


def _signed(doc: dict, signing_key) -> dict:
    from al_core.receipt import sign_receipt

    return sign_receipt(doc, signing_key)


def _attestation(signing_key) -> dict:
    return _signed({
        "kind": ATTESTATION_KIND, "org": "acme", "issued_ts": "2026-07-12T00:00:00.000Z",
        "posture": {"mode": "balanced"}, "evidence": {"events": 1},
        "chain": {"verified": True, "length": 1, "head": "sha256:" + "a" * 64},
        "evidence_level": "AEL-2",
    }, signing_key)


def _bundle(signing_key) -> dict:
    return _signed({
        "kind": RULE_BUNDLE_KIND, "bundle_id": "b1",
        "created_ts": "2026-07-12T00:00:00.000Z", "approved_by": "op@acme",
        "rules": [{"rule_id": "learned.x", "pattern": "evil", "action": "block"}],
    }, signing_key)


def test_verify_attestation_ok(signing_key, public_key):
    doc = _attestation(signing_key)
    assert verify_attestation(doc, public_key) == doc["record_hash"]


def test_attestation_wrong_kind_is_rejected(signing_key, public_key):
    doc = _attestation(signing_key)
    doc["kind"] = "al.something-else.v1"
    with pytest.raises(MalformedReceipt, match="not an attestation"):
        verify_attestation(doc, public_key)


def test_attestation_missing_field_is_rejected(signing_key, public_key):
    doc = _attestation(signing_key)
    del doc["chain"]
    with pytest.raises(MalformedReceipt, match="missing required field"):
        verify_attestation(doc, public_key)


def test_verify_rule_bundle_ok(signing_key, public_key):
    doc = _bundle(signing_key)
    assert verify_rule_bundle(doc, public_key) == doc["record_hash"]


def test_rule_bundle_wrong_kind_is_rejected(signing_key, public_key):
    doc = _bundle(signing_key)
    doc["kind"] = ATTESTATION_KIND
    with pytest.raises(MalformedReceipt, match="not a rule bundle"):
        verify_rule_bundle(doc, public_key)


def test_rule_bundle_rules_must_be_a_list(signing_key, public_key):
    doc = _bundle(signing_key)
    doc["rules"] = {"rule_id": "sneaky"}
    with pytest.raises(MalformedReceipt, match="must be a list"):
        verify_rule_bundle(doc, public_key)


def test_cli_recognizes_attestation_and_bundle(tmp_path, signing_key, public_key):
    pub = tmp_path / "k.pub"
    pub.write_text(public_key_hex(public_key), encoding="utf-8")

    att = tmp_path / "attestation.json"
    att.write_text(json.dumps(_attestation(signing_key)), encoding="utf-8")
    assert verify_main([str(att), "--pubkey", str(pub)]) == 0

    bundle = tmp_path / "bundle.json"
    bundle.write_text(json.dumps(_bundle(signing_key)), encoding="utf-8")
    assert verify_main([str(bundle), "--pubkey", str(pub)]) == 0


def test_cli_rejects_a_non_object_non_array_document(tmp_path, ledger):
    """A bare JSON scalar is neither a receipt nor a chain — refuse it."""
    _, _, pub = ledger                       # the real public key, so the parse
    bad = tmp_path / "bad.json"              # guard is what rejects the file
    bad.write_text('"just a string"', encoding="utf-8")
    assert verify_main([str(bad), "--pubkey", str(pub)]) == 2


def test_canonicalizer_rejects_non_string_object_keys():
    from al_verify.canonical import CanonicalizationError, canonicalize

    with pytest.raises(CanonicalizationError, match="object keys must be strings"):
        canonicalize({1: "not a string key"})
