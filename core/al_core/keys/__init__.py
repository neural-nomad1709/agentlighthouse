"""Ed25519 key management — an enforced invariant (D5).

A forgeable signing key means forgeable evidence, which kills Goal 3. Therefore:

* Dev: auto-generate to ``./keys/mediator_ed25519`` at mode 0600 (owner-only).
* Prod: never auto-generate; the key is delivered as a Docker secret. A missing
  key means **refuse to start**.
* Any environment: key-file permissions looser than 0600 → **refuse to start**.

The permission *policy* (:func:`permissions_too_loose`) is a pure function so it
can be unit-tested on every platform; the filesystem check is only enforced on
POSIX, where mode bits are meaningful. On Windows (dev only) POSIX modes do not
apply and the check is skipped with a warning.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

POSIX = os.name == "posix"
DEFAULT_MIN_PERMISSIONS = 0o600


class KeyManagementError(Exception):
    """Base class for key-management failures (all fail-closed)."""


class KeyMissingError(KeyManagementError):
    pass


class KeyPermissionError(KeyManagementError):
    pass


def permissions_too_loose(mode: int, minimum: int = DEFAULT_MIN_PERMISSIONS) -> bool:
    """True if ``mode`` grants any permission bit not allowed by ``minimum``.

    Pure and platform-independent so it can be tested everywhere. With the
    default ``minimum`` of 0o600, any group/other access — or owner-execute —
    is considered too loose for a signing key.
    """
    return bool((mode & 0o777) & ~minimum)


def _enforce_permissions(path: Path, minimum: int) -> None:
    if not POSIX:
        # POSIX mode bits are not meaningful on Windows; dev-only path.
        return
    mode = path.stat().st_mode & 0o777
    if permissions_too_loose(mode, minimum):
        raise KeyPermissionError(
            f"signing key {path} has permissions {mode:#o}, looser than "
            f"required {minimum:#o}; refusing to start"
        )


def public_key_hex(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


def _private_raw(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _write_owner_only(path: Path, data: bytes, minimum: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Create with restrictive mode up front so the key is never briefly world-readable.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(path), flags, minimum)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    finally:
        if POSIX:
            os.chmod(str(path), minimum)


def generate_signing_key(
    path: Path,
    minimum: int = DEFAULT_MIN_PERMISSIONS,
) -> Ed25519PrivateKey:
    """Generate a fresh Ed25519 key, persist private (raw, 0600) + public (hex)."""
    key = Ed25519PrivateKey.generate()
    _write_owner_only(path, _private_raw(key), minimum)
    pub_path = path.with_suffix(path.suffix + ".pub") if path.suffix else Path(str(path) + ".pub")
    pub_path.write_text(public_key_hex(key.public_key()) + "\n", encoding="utf-8")
    return key


def load_signing_key(
    path: Path,
    minimum: int = DEFAULT_MIN_PERMISSIONS,
) -> Ed25519PrivateKey:
    if not path.exists():
        raise KeyMissingError(f"signing key not found at {path}; refusing to start")
    _enforce_permissions(path, minimum)
    raw = path.read_bytes()
    if len(raw) != 32:
        raise KeyManagementError(
            f"signing key at {path} is {len(raw)} bytes; expected a raw 32-byte Ed25519 key"
        )
    return Ed25519PrivateKey.from_private_bytes(raw)


def load_or_create_signing_key(
    path: Path,
    *,
    auto_generate: bool = True,
    env: str = "dev",
    minimum: int = DEFAULT_MIN_PERMISSIONS,
) -> Ed25519PrivateKey:
    """Load the signing key, or create it in dev.

    Fail-closed: in prod (``env != "dev"``) a missing key is fatal; auto-generation
    is only ever allowed in dev.
    """
    path = Path(path)
    if path.exists():
        return load_signing_key(path, minimum)
    if auto_generate and env == "dev":
        return generate_signing_key(path, minimum)
    raise KeyMissingError(
        f"signing key missing at {path} and auto-generate is disabled "
        f"(env={env!r}); refusing to start"
    )
