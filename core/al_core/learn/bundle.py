"""The review gate: candidates in, a **signed** rule bundle out.

A rule bundle changes what the mediator blocks. That makes it code, in the only
sense that matters — so it is treated like code that ships:

* a human approves specific candidates (nothing auto-promotes);
* the approved set is canonicalized and **Ed25519-signed with the mediator key**;
* the loader **verifies before it loads**. An unsigned or tampered bundle is
  *refused* — not loaded-with-a-warning, not loaded-in-audit-mode. A rule you
  cannot attribute is a rule an attacker may have written, and the whole point
  of the learning loop is that it cannot be used to teach the plane to allow.

The bundle verifies with the standalone ``al-verify`` too, so an auditor can
check which rules a deployment is enforcing without running any of our code.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from al_verify.verify import RULE_BUNDLE_KIND, VerificationError, verify_rule_bundle

from ..receipt import sign_receipt, utcnow_iso
from .miner import Candidate


class UnsignedBundleError(RuntimeError):
    """A rule bundle failed verification and was refused (fail-closed)."""


def build_bundle(
    approved: Sequence[Candidate],
    signing_key: Ed25519PrivateKey,
    *,
    bundle_id: str,
    approved_by: str,
) -> dict[str, Any]:
    """Sign an operator-approved set of candidates into a rule bundle."""
    doc: dict[str, Any] = {
        "kind": RULE_BUNDLE_KIND,
        "bundle_id": bundle_id,
        "created_ts": utcnow_iso(),
        "approved_by": approved_by,
        "rules": [c.to_rule() for c in approved],
    }
    return sign_receipt(doc, signing_key)


def load_bundle(path: str | Path, public_key: Ed25519PublicKey) -> dict[str, Any]:
    """Verify then load. Raises ``UnsignedBundleError`` on ANY failure.

    The order is the point: nothing is parsed into policy until the signature
    checks out."""
    p = Path(path)
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UnsignedBundleError(f"cannot read rule bundle {p}: {exc}") from exc
    if not isinstance(doc, dict):
        raise UnsignedBundleError(f"rule bundle {p} must be a JSON object")
    try:
        verify_rule_bundle(doc, public_key)
    except VerificationError as exc:
        raise UnsignedBundleError(
            f"refusing rule bundle {p}: {type(exc).__name__}: {exc}") from exc
    return doc


__all__ = ["UnsignedBundleError", "build_bundle", "load_bundle"]
