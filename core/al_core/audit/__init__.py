"""Audit ledger: append-only JSONL (canonical) + SQLite mirror + startup verify.

The ``Ledger`` is the single writer of evidence. It owns the ``ReceiptSigner``
(hash chain), appends each signed receipt to the canonical JSONL first, then
mirrors it into SQLite for queries. On construction it re-verifies the existing
JSONL chain against the mediator public key and refuses to run on tamper
(invariant #7), then resumes the chain from the persisted tail.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Iterator, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from al_verify.canonical import canonicalize
from al_verify.verify import GENESIS_PREV_HASH, verify_chain

from ..receipt import ReceiptSigner
from .db import SqliteMirror

log = logging.getLogger("al.audit")


class AuditTamperError(Exception):
    """Raised when the on-disk JSONL chain fails verification on startup."""


class JsonlLedger:
    """Append-only canonical receipt log (one JCS line per receipt)."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def append(self, receipt: dict[str, Any]) -> None:
        line = canonicalize(receipt).decode("utf-8")
        with self._path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(line + "\n")

    def read_all(self) -> list[dict[str, Any]]:
        return list(self.iter_records())

    def iter_records(self) -> Iterator[dict[str, Any]]:
        if not self._path.exists():
            return
        with self._path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditTamperError(
                        f"{self._path}:{lineno}: not valid JSON: {exc}"
                    ) from exc


class Ledger:
    """Signs, persists, verifies-on-startup, and mirrors receipts."""

    def __init__(
        self,
        signing_key: Ed25519PrivateKey,
        public_key: Ed25519PublicKey,
        *,
        jsonl_path: str | Path,
        db_path: str | Path,
        dsn: str | None = None,
    ) -> None:
        self._jsonl = JsonlLedger(jsonl_path)
        # The mirror is a query surface, never the source of truth — swapping
        # SQLite for Postgres (the concurrent-writer path) changes nothing about
        # the evidence, only who may write the mirror at once.
        if dsn:
            from .pg import PostgresMirror

            self._db = PostgresMirror(dsn)
        else:
            self._db = SqliteMirror(db_path)

        # 1. Verify the existing chain end-to-end; refuse to run on tamper.
        records = self._jsonl.read_all()
        verify_chain(records, public_key)  # raises VerificationError on tamper

        # 2. Reconcile the mirror from the canonical log (mirror is disposable).
        self._db.reconcile(records)

        # 3. Resume the chain from the persisted tail.
        if records:
            tail = records[-1]
            start_seq = int(tail["seq"]) + 1
            prev_hash = tail["record_hash"]
        else:
            start_seq, prev_hash = 0, GENESIS_PREV_HASH
        self._signer = ReceiptSigner(signing_key, start_seq=start_seq, prev_hash=prev_hash)

    @property
    def db(self):  # noqa: ANN201 — SqliteMirror | PostgresMirror (same surface)
        return self._db

    @property
    def next_seq(self) -> int:
        return self._signer.next_seq

    def last_config_hash(self) -> str | None:
        """policy_hash of the most recent config_change receipt, if any."""
        return self._db.last_config_hash()

    def record(self, **fields: Any) -> dict[str, Any]:
        """Sign, append to JSONL (canonical), then mirror. Returns the receipt."""
        receipt = self._signer.record(**fields)
        self._jsonl.append(receipt)  # source of truth first
        try:
            self._db.upsert_event(receipt)
        except Exception:  # noqa: BLE001 — mirror failure must not lose evidence
            log.exception("SQLite mirror write failed for seq=%s (JSONL is intact)", receipt["seq"])
        return receipt

    def verify(self, public_key: Ed25519PublicKey) -> int:
        return verify_chain(self._jsonl.read_all(), public_key)

    def close(self) -> None:
        self._db.close()


def verify_ledger_file(jsonl_path: str | Path, public_key: Ed25519PublicKey) -> int:
    """Standalone helper: verify a JSONL ledger's chain. Returns record count."""
    return verify_chain(JsonlLedger(jsonl_path).read_all(), public_key)


__all__ = [
    "AuditTamperError",
    "JsonlLedger",
    "Ledger",
    "SqliteMirror",
    "verify_ledger_file",
]
