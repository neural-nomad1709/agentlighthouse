"""Key management invariants (keys_test — Phase 0 acceptance)."""

from __future__ import annotations

import os

import pytest

from al_core.keys import (
    KeyMissingError,
    KeyPermissionError,
    generate_signing_key,
    load_or_create_signing_key,
    load_signing_key,
    permissions_too_loose,
)

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits only")


@pytest.mark.parametrize(
    "mode,expected",
    [
        (0o600, False),
        (0o400, False),
        (0o640, True),   # group read
        (0o604, True),   # other read
        (0o660, True),   # group rw
        (0o700, True),   # owner execute is also 'looser' than 0600
        (0o777, True),
    ],
)
def test_permission_policy(mode, expected):
    assert permissions_too_loose(mode) is expected


def test_generate_and_load_roundtrip(tmp_path):
    key = generate_signing_key(tmp_path / "k_ed25519")
    loaded = load_signing_key(tmp_path / "k_ed25519")
    msg = b"receipt-bytes"
    # Signature from the loaded key verifies against the original public key.
    loaded_sig = loaded.sign(msg)
    key.public_key().verify(loaded_sig, msg)


def test_public_key_file_written(tmp_path):
    generate_signing_key(tmp_path / "k_ed25519")
    pub = tmp_path / "k_ed25519.pub"
    assert pub.exists()
    assert len(pub.read_text().strip()) == 64  # hex-encoded 32-byte key


def test_missing_key_in_prod_refuses(tmp_path):
    with pytest.raises(KeyMissingError):
        load_or_create_signing_key(
            tmp_path / "absent_ed25519", auto_generate=False, env="prod"
        )


def test_missing_key_in_dev_autogenerates(tmp_path):
    key = load_or_create_signing_key(
        tmp_path / "new_ed25519", auto_generate=True, env="dev"
    )
    assert (tmp_path / "new_ed25519").exists()
    assert key is not None


def test_prod_never_autogenerates_even_if_flag_set(tmp_path):
    # auto_generate only applies in dev; prod must refuse a missing key.
    with pytest.raises(KeyMissingError):
        load_or_create_signing_key(
            tmp_path / "absent_ed25519", auto_generate=True, env="prod"
        )


@posix_only
def test_loose_permissions_refuse_to_load(tmp_path):
    path = tmp_path / "loose_ed25519"
    generate_signing_key(path)
    os.chmod(path, 0o644)  # world-readable
    with pytest.raises(KeyPermissionError):
        load_signing_key(path)
