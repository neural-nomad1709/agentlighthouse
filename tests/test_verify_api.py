"""Verifier API edge/fail-closed paths (100% target on evidence code)."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from al_verify.verify import (
    MalformedReceipt,
    SignatureInvalid,
    compute_record_hash,
    load_public_key,
    verify_receipt,
    verify_signature,
)


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


def test_load_public_key_from_hex(key):
    hexed = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    assert load_public_key(hexed) is not None


def test_load_public_key_from_raw_bytes(key):
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert load_public_key(raw) is not None


def test_load_public_key_from_pem(key):
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert load_public_key(pem) is not None
    assert load_public_key(pem.decode("utf-8")) is not None


def test_load_public_key_rejects_non_ed25519():
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_pem = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    with pytest.raises(MalformedReceipt):
        load_public_key(rsa_pem)


def test_load_public_key_garbage():
    with pytest.raises(Exception):
        load_public_key("not-a-key")


def _signed(key):
    r = {
        "v": 1, "seq": 0, "ts": "2026-07-10T00:00:00.000Z",
        "actor": "spiffe://a/agent/b", "action": "fetch", "target": "https://e.com",
        "verdict": "allow", "prev_hash": "sha256:" + "0" * 64,
    }
    r["record_hash"] = compute_record_hash(r)
    from al_verify.verify import signing_input
    r["sig"] = "ed25519:" + base64.b64encode(key.sign(signing_input(r))).decode()
    return r


def test_missing_required_field_is_malformed(key):
    r = _signed(key)
    del r["record_hash"]
    with pytest.raises(MalformedReceipt):
        verify_receipt(r, key.public_key())


def test_missing_sig_is_malformed(key):
    r = _signed(key)
    del r["sig"]
    with pytest.raises(MalformedReceipt):
        verify_signature(r, key.public_key())


def test_bad_sig_prefix_is_malformed(key):
    r = _signed(key)
    r["sig"] = "notaprefix:abc"
    with pytest.raises(MalformedReceipt):
        verify_signature(r, key.public_key())


def test_bad_base64_sig_is_malformed(key):
    r = _signed(key)
    r["sig"] = "ed25519:!!!not-base64!!!"
    with pytest.raises(MalformedReceipt):
        verify_signature(r, key.public_key())


def test_wrong_key_fails_signature(key):
    r = _signed(key)
    other = Ed25519PrivateKey.generate()
    with pytest.raises(SignatureInvalid):
        verify_signature(r, other.public_key())


def test_good_receipt_verifies(key):
    assert verify_receipt(_signed(key), key.public_key()).startswith("sha256:")


def test_verify_receipt_prev_hash_mismatch(key):
    from al_verify.verify import ChainBroken

    r = _signed(key)
    with pytest.raises(ChainBroken):
        verify_receipt(r, key.public_key(), expected_prev_hash="sha256:" + "1" * 64)


def test_load_public_key_64_chars_not_hex():
    # 64 chars but not valid hex -> falls through to PEM attempt -> fails.
    with pytest.raises(Exception):
        load_public_key("z" * 64)


def test_load_public_key_non_utf8_non_32_bytes():
    with pytest.raises(Exception):
        load_public_key(b"\xff\xfe\xfd\xfc" * 3)  # 12 bytes, not utf-8, not PEM
