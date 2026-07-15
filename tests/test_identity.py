"""Agent identity registry (identity_test — Phase 0 acceptance)."""

from __future__ import annotations

import pytest

from al_core.identity import (
    IdentityRegistry,
    InvalidSpiffeId,
    parse_spiffe,
    spiffe_id,
)


def test_spiffe_id_roundtrip():
    sid = spiffe_id("acme", "claude-code")
    assert sid == "spiffe://acme/agent/claude-code"
    assert parse_spiffe(sid) == ("acme", "claude-code")


def test_invalid_spiffe_rejected():
    with pytest.raises(InvalidSpiffeId):
        spiffe_id("Acme!", "x")  # uppercase/illegal char
    with pytest.raises(InvalidSpiffeId):
        parse_spiffe("https://acme/agent/x")


def test_issue_binds_identity_and_key():
    reg = IdentityRegistry()
    creds = reg.issue("acme", "claude-code")
    assert creds.identity.spiffe_id == "spiffe://acme/agent/claude-code"
    assert len(creds.identity.public_key_hex) == 64
    # Per-agent private key matches the stored public key.
    from al_core.keys import public_key_hex
    assert public_key_hex(creds.private_key.public_key()) == creds.identity.public_key_hex


def test_no_identity_denies():
    reg = IdentityRegistry()
    # Unknown agent, or missing credentials -> None (caller denies).
    assert reg.authenticate("spiffe://acme/agent/ghost", "tok") is None
    assert reg.authenticate(None, None) is None
    assert reg.authenticate("spiffe://acme/agent/ghost", None) is None


def test_authenticate_valid_and_wrong_token():
    reg = IdentityRegistry()
    creds = reg.issue("acme", "claude-code")
    assert reg.authenticate(creds.identity.spiffe_id, creds.token) is not None
    assert reg.authenticate(creds.identity.spiffe_id, "wrong-token") is None


def test_token_not_stored_in_plaintext():
    reg = IdentityRegistry()
    creds = reg.issue("acme", "claude-code")
    assert creds.token not in creds.identity.token_hash
    assert creds.identity.token_hash.startswith("sha256:")


def test_duplicate_issue_rejected():
    from al_core.identity import DuplicateIdentity

    reg = IdentityRegistry()
    reg.issue("acme", "claude-code")
    with pytest.raises(DuplicateIdentity):
        reg.issue("acme", "claude-code")


def test_persistence_roundtrip(tmp_path):
    path = tmp_path / "identities.json"
    reg = IdentityRegistry(path)
    creds = reg.issue("acme", "claude-code")

    reloaded = IdentityRegistry(path)
    ident = reloaded.get(creds.identity.spiffe_id)
    assert ident is not None
    assert ident.public_key_hex == creds.identity.public_key_hex
    # Token still authenticates after reload (hash persisted).
    assert reloaded.authenticate(creds.identity.spiffe_id, creds.token) is not None
