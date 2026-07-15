"""Receipt verification: hash chain + Ed25519 signature.

This module defines the *canonical truth* about how a receipt is hashed and
signed. ``al-core`` imports these functions when building receipts so the
producing and verifying sides are provably symmetric; a third party can verify
with only this package installed (no ``al-core``).

Hashing/signing procedure (receipt schema v1):
    1. ``record_hash`` = "sha256:" + hex( SHA-256( JCS(receipt \\ {record_hash, sig}) ) )
       — commits to every field except record_hash and sig, *including* prev_hash.
    2. ``sig``         = "ed25519:" + b64( Ed25519.sign( JCS(receipt \\ {sig}) ) )
       — signs the record_hash together with all other content.
    3. Chain: ``prev_hash`` of record N equals ``record_hash`` of record N-1.
       The genesis record's prev_hash is ``GENESIS_PREV_HASH``.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .canonical import canonicalize

HASH_PREFIX = "sha256:"
SIG_PREFIX = "ed25519:"
GENESIS_PREV_HASH = HASH_PREFIX + "0" * 64


class VerificationError(Exception):
    """Base class for all receipt verification failures (fail-closed)."""


class RecordHashMismatch(VerificationError):
    pass


class SignatureInvalid(VerificationError):
    pass


class ChainBroken(VerificationError):
    pass


class MalformedReceipt(VerificationError):
    pass


def sha256_hex(data: bytes) -> str:
    return HASH_PREFIX + hashlib.sha256(data).hexdigest()


def _without(receipt: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {k: v for k, v in receipt.items() if k not in keys}


def record_hash_input(receipt: dict[str, Any]) -> bytes:
    """Canonical bytes that ``record_hash`` is computed over."""
    return canonicalize(_without(receipt, "record_hash", "sig"))


def signing_input(receipt: dict[str, Any]) -> bytes:
    """Canonical bytes that ``sig`` is computed over (includes record_hash)."""
    return canonicalize(_without(receipt, "sig"))


def compute_record_hash(receipt: dict[str, Any]) -> str:
    return sha256_hex(record_hash_input(receipt))


def _load_pem(data: bytes) -> Ed25519PublicKey:
    key = load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise MalformedReceipt("public key is not an Ed25519 key")
    return key


def load_public_key(source: str | bytes) -> Ed25519PublicKey:
    """Load an Ed25519 public key from 64-char hex, raw 32 bytes, or PEM.

    Accepts either a string (hex or PEM text) or bytes. Bytes of exactly length
    32 are treated as a raw key; other bytes are decoded as text first, so a
    ``.pub`` file containing hex (our on-disk format) loads correctly.
    """
    if isinstance(source, bytes):
        if len(source) == 32:
            return Ed25519PublicKey.from_public_bytes(source)
        try:
            source = source.decode("utf-8")
        except UnicodeDecodeError:
            return _load_pem(source)
    text = source.strip()
    compact = "".join(text.split())
    if len(compact) == 64:
        try:
            return Ed25519PublicKey.from_public_bytes(bytes.fromhex(compact))
        except ValueError:
            pass
    return _load_pem(text.encode("utf-8"))


def _require(receipt: dict[str, Any], field: str) -> Any:
    if field not in receipt:
        raise MalformedReceipt(f"receipt missing required field: {field!r}")
    return receipt[field]


def verify_record_hash(receipt: dict[str, Any]) -> None:
    stored = _require(receipt, "record_hash")
    expected = compute_record_hash(receipt)
    if stored != expected:
        raise RecordHashMismatch(
            f"record_hash mismatch: stored {stored!r} != computed {expected!r}"
        )


def verify_signature(receipt: dict[str, Any], public_key: Ed25519PublicKey) -> None:
    sig = _require(receipt, "sig")
    if not isinstance(sig, str) or not sig.startswith(SIG_PREFIX):
        raise MalformedReceipt(f"sig must be an '{SIG_PREFIX}...' string")
    try:
        raw = base64.b64decode(sig[len(SIG_PREFIX):], validate=True)
    except (ValueError, TypeError) as exc:
        raise MalformedReceipt(f"sig is not valid base64: {exc}") from exc
    try:
        public_key.verify(raw, signing_input(receipt))
    except InvalidSignature as exc:
        raise SignatureInvalid("Ed25519 signature does not verify") from exc


def verify_receipt(
    receipt: dict[str, Any],
    public_key: Ed25519PublicKey,
    expected_prev_hash: str | None = None,
) -> str:
    """Verify one receipt fully. Returns its ``record_hash`` (for chaining).

    Raises a ``VerificationError`` subclass on any failure — never returns on a
    bad receipt (fail-closed).
    """
    verify_record_hash(receipt)
    verify_signature(receipt, public_key)
    if expected_prev_hash is not None:
        actual = _require(receipt, "prev_hash")
        if actual != expected_prev_hash:
            raise ChainBroken(
                f"prev_hash mismatch at seq {receipt.get('seq')}: "
                f"expected {expected_prev_hash!r}, found {actual!r}"
            )
    return receipt["record_hash"]


ATTESTATION_KIND = "al.posture-attestation.v1"
RULE_BUNDLE_KIND = "al.rule-bundle.v1"


def verify_rule_bundle(
    bundle: dict[str, Any], public_key: Ed25519PublicKey
) -> str:
    """Verify a signed learned-rule bundle. Returns its ``record_hash``.

    A rule bundle changes what the mediator blocks, so it is *code* in the only
    sense that matters. It is signed with the mediator key and verified before
    load — an unsigned or tampered bundle is refused, never "loaded with a
    warning". Same canonicalization + signature procedure as a receipt, so this
    dependency-minimal verifier can check one with no runtime present.
    """
    kind = _require(bundle, "kind")
    if kind != RULE_BUNDLE_KIND:
        raise MalformedReceipt(
            f"not a rule bundle: kind={kind!r} (want {RULE_BUNDLE_KIND!r})")
    for field in ("bundle_id", "created_ts", "rules", "approved_by"):
        _require(bundle, field)
    if not isinstance(bundle["rules"], list):
        raise MalformedReceipt("rule bundle 'rules' must be a list")
    verify_record_hash(bundle)
    verify_signature(bundle, public_key)
    return bundle["record_hash"]


def verify_attestation(
    attestation: dict[str, Any], public_key: Ed25519PublicKey
) -> str:
    """Verify a signed per-org posture attestation. Returns its ``record_hash``.

    An attestation is a standalone signed statement (no ``prev_hash`` chain) —
    it *quotes* the chain head it was cut from, so an auditor can tie it back to
    the ledger. It uses the same canonicalization and signature procedure as a
    receipt, so this verifier needs no AgentLighthouse runtime and no
    governance code to check one.
    """
    kind = _require(attestation, "kind")
    if kind != ATTESTATION_KIND:
        raise MalformedReceipt(
            f"not an attestation: kind={kind!r} (want {ATTESTATION_KIND!r})")
    for field in ("org", "issued_ts", "chain", "posture", "evidence"):
        _require(attestation, field)
    verify_record_hash(attestation)
    verify_signature(attestation, public_key)
    return attestation["record_hash"]


def verify_chain(
    receipts: Iterable[dict[str, Any]],
    public_key: Ed25519PublicKey,
    genesis_prev_hash: str = GENESIS_PREV_HASH,
) -> int:
    """Verify an ordered sequence of receipts as a hash chain.

    Returns the number of receipts verified. Raises on the first failure.
    """
    expected_prev = genesis_prev_hash
    count = 0
    last_seq: int | None = None
    for receipt in receipts:
        seq = receipt.get("seq")
        if last_seq is not None and isinstance(seq, int) and seq != last_seq + 1:
            raise ChainBroken(f"non-contiguous seq: {last_seq} -> {seq}")
        expected_prev = verify_receipt(receipt, public_key, expected_prev)
        last_seq = seq if isinstance(seq, int) else last_seq
        count += 1
    return count
