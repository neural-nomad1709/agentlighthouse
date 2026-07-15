"""al-verify — standalone AgentLighthouse receipt verifier (MIT).

Public API is intentionally tiny and dependency-light so third parties can audit
AgentLighthouse evidence without installing al-core.
"""

from __future__ import annotations

from .canonical import CanonicalizationError, canonicalize
from .verify import (
    GENESIS_PREV_HASH,
    HASH_PREFIX,
    SIG_PREFIX,
    ChainBroken,
    MalformedReceipt,
    RecordHashMismatch,
    SignatureInvalid,
    VerificationError,
    compute_record_hash,
    load_public_key,
    record_hash_input,
    sha256_hex,
    signing_input,
    verify_chain,
    verify_receipt,
    verify_signature,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "canonicalize",
    "CanonicalizationError",
    "GENESIS_PREV_HASH",
    "HASH_PREFIX",
    "SIG_PREFIX",
    "VerificationError",
    "ChainBroken",
    "MalformedReceipt",
    "RecordHashMismatch",
    "SignatureInvalid",
    "compute_record_hash",
    "load_public_key",
    "record_hash_input",
    "sha256_hex",
    "signing_input",
    "verify_chain",
    "verify_receipt",
    "verify_signature",
]
