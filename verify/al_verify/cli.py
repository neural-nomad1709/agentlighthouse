"""``al-verify`` command line: verify a receipt, a receipt chain, or an attestation.

Usage:
    al-verify RECEIPT.json      [--pubkey KEY]
    al-verify LEDGER.jsonl      [--pubkey KEY]   # newline-delimited or JSON array
    al-verify ATTESTATION.json  [--pubkey KEY]   # signed per-org posture (Phase 6)

KEY may be a path to a public-key file (64-hex or PEM) or an inline 64-hex
string. Defaults to ``keys/mediator_ed25519.pub``. Exit code is 0 only when
every receipt verifies; any failure exits non-zero (fail-closed).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .verify import (
    ATTESTATION_KIND,
    RULE_BUNDLE_KIND,
    VerificationError,
    load_public_key,
    verify_attestation,
    verify_chain,
    verify_receipt,
    verify_rule_bundle,
)

DEFAULT_PUBKEY = "keys/mediator_ed25519.pub"


def _load_pubkey(arg: str):
    # An existing path wins; otherwise treat the argument as an inline hex key.
    p = Path(arg)
    if p.exists():
        return load_public_key(p.read_bytes())
    return load_public_key(arg)


def _parse_receipts(text: str) -> tuple[list[dict[str, Any]], bool]:
    """Return (receipts, is_chain). is_chain True for arrays / JSONL."""
    stripped = text.strip()
    if not stripped:
        raise ValueError("input is empty")
    try:
        doc = json.loads(stripped)
    except json.JSONDecodeError:
        # Fall back to newline-delimited JSON (one receipt per line).
        receipts = [json.loads(line) for line in stripped.splitlines() if line.strip()]
        return receipts, True
    if isinstance(doc, dict):
        return [doc], False
    if isinstance(doc, list):
        return doc, True
    raise ValueError("top-level JSON must be an object (receipt) or array (chain)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="al-verify",
        description="Independently verify AgentLighthouse receipts (hash chain + Ed25519).",
    )
    parser.add_argument("receipt", help="path to a receipt .json or a .jsonl ledger")
    parser.add_argument(
        "--pubkey",
        default=os.environ.get("AL_PUBKEY", DEFAULT_PUBKEY),
        help=f"public key file or inline hex (default: {DEFAULT_PUBKEY})",
    )
    parser.add_argument("--quiet", action="store_true", help="only report the final verdict")
    parser.add_argument("--version", action="version", version=f"al-verify {__version__}")
    args = parser.parse_args(argv)

    try:
        public_key = _load_pubkey(args.pubkey)
    except Exception as exc:  # noqa: BLE001 — surface any key-loading failure clearly
        print(f"FAIL: could not load public key from {args.pubkey!r}: {exc}", file=sys.stderr)
        return 2

    try:
        text = Path(args.receipt).read_text(encoding="utf-8")
        receipts, is_chain = _parse_receipts(text)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAIL: could not read receipts from {args.receipt!r}: {exc}", file=sys.stderr)
        return 2

    try:
        if is_chain:
            n = verify_chain(receipts, public_key)
            if not args.quiet:
                print(f"chain of {n} receipt(s) verified from genesis")
        elif receipts[0].get("kind") == RULE_BUNDLE_KIND:
            bundle = receipts[0]
            verify_rule_bundle(bundle, public_key)
            if not args.quiet:
                print(
                    f"rule bundle {bundle.get('bundle_id')!r} verified "
                    f"({len(bundle.get('rules', []))} rule(s), "
                    f"approved by {bundle.get('approved_by')!r})"
                )
        elif receipts[0].get("kind") == ATTESTATION_KIND:
            att = receipts[0]
            verify_attestation(att, public_key)
            if not args.quiet:
                chain = att.get("chain", {})
                print(
                    f"posture attestation for org={att.get('org')!r} verified "
                    f"(level {att.get('evidence_level')}, "
                    f"{att.get('evidence', {}).get('events')} events, "
                    f"chain head {str(chain.get('head'))[:23]}...)"
                )
        else:
            rec = receipts[0]
            verify_receipt(rec, public_key)
            if not args.quiet:
                print(
                    f"receipt seq={rec.get('seq')} action={rec.get('action')!r} "
                    f"verdict={rec.get('verdict')!r} verified"
                )
    except VerificationError as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print("OK")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
