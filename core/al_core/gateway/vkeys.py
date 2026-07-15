"""Per-user virtual keys + budgets for the reverse proxy (L1).

Agents/users never hold real provider API keys — they hold **virtual keys**
(`alk_...`) minted here. The reverse proxy authenticates the virtual key,
enforces its budget, then swaps in the real upstream key (config `SecretStr`,
env/secrets only). Over-budget → deny (``BUDGET_EXCEEDED``) — the
denial-of-wallet control.

Storage mirrors the identity registry: JSON file, token stored only as a
SHA-256 hash, plaintext shown once at issuance. Budget counters live in the
Phase-0 SQLite ``quotas`` table (operational state, not evidence — the JSONL
receipts remain the source of truth for *what happened*).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import secrets
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable

from ..audit.db import SqliteMirror
from ..receipt import utcnow_iso

TOKEN_PREFIX = "alk_"


def _hash_token(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


def _utc_today() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")


@dataclass(frozen=True)
class VirtualKey:
    """One user's key. ``None`` limits mean unlimited; 0 means deny-all."""

    key_id: str
    user: str
    token_hash: str
    created_ts: str
    max_requests_per_day: int | None = None
    max_tokens_per_day: int | None = None
    disabled: bool = False
    org: str | None = None  # tenant this key bills + reports to (Phase 6)

    @property
    def actor(self) -> str:
        """Receipt actor binding decisions to the human, not the key.

        With an org, the actor is SPIFFE-shaped (``spiffe://<org>/user/<name>``)
        so tenancy scoping sees an LLM call as the tenant's own event — without
        it, a key's receipts land in the org-less ``system`` bucket and its own
        tenant could not see them. Org-less keys keep the Phase-1 ``user:<name>``
        form (single-tenant deployments are unaffected)."""
        if self.org:
            return f"spiffe://{self.org}/user/{self.user}"
        return f"user:{self.user}"

    def to_json(self) -> dict:
        return {
            "key_id": self.key_id,
            "user": self.user,
            "token_hash": self.token_hash,
            "created_ts": self.created_ts,
            "max_requests_per_day": self.max_requests_per_day,
            "max_tokens_per_day": self.max_tokens_per_day,
            "disabled": self.disabled,
            "org": self.org,
        }

    @classmethod
    def from_json(cls, d: dict) -> "VirtualKey":
        return cls(**d)


class VirtualKeyStore:
    """JSON-file-backed store. Lookup is by token hash — fail-closed on any miss."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path else None
        self._by_id: dict[str, VirtualKey] = {}
        if self._path and self._path.exists():
            for d in json.loads(self._path.read_text(encoding="utf-8")):
                vk = VirtualKey.from_json(d)
                self._by_id[vk.key_id] = vk

    def _save(self) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps([k.to_json() for k in self._by_id.values()], indent=2),
            encoding="utf-8",
        )

    def issue(
        self,
        user: str,
        *,
        org: str | None = None,
        max_requests_per_day: int | None = None,
        max_tokens_per_day: int | None = None,
    ) -> tuple[VirtualKey, str]:
        """Mint a key. Returns (record, plaintext token) — token is not recoverable."""
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        vk = VirtualKey(
            key_id="vk_" + secrets.token_hex(8),
            user=user,
            org=org,
            token_hash=_hash_token(token),
            created_ts=utcnow_iso(),
            max_requests_per_day=max_requests_per_day,
            max_tokens_per_day=max_tokens_per_day,
        )
        self._by_id[vk.key_id] = vk
        self._save()
        return vk, token

    def authenticate(self, token: str | None) -> VirtualKey | None:
        """Return the live key for ``token`` or None (caller denies).

        Constant-time hash comparison; disabled keys never authenticate.
        """
        if not token:
            return None
        presented = _hash_token(token)
        for vk in self._by_id.values():
            if secrets.compare_digest(vk.token_hash, presented):
                return None if vk.disabled else vk
        return None

    def revoke(self, key_id: str) -> bool:
        vk = self._by_id.get(key_id)
        if vk is None:
            return False
        self._by_id[key_id] = replace(vk, disabled=True)
        self._save()
        return True

    def get(self, key_id: str) -> VirtualKey | None:
        return self._by_id.get(key_id)

    def list(self) -> list[VirtualKey]:
        return list(self._by_id.values())


class BudgetLedger:
    """Per-key daily budgets over the SQLite ``quotas`` table.

    ``try_consume`` is the pre-flight gate (atomic check-and-increment under
    the DB lock); ``add_usage`` records post-hoc token usage unconditionally —
    usage that already happened must never be dropped, even if it lands the
    key over budget (the *next* pre-flight then denies).
    """

    def __init__(self, db: SqliteMirror, *, today: Callable[[], str] | None = None) -> None:
        self._db = db
        self._today = today or _utc_today

    def try_consume(self, key: VirtualKey, *, requests: int = 0, tokens: int = 0) -> bool:
        ok, _, _ = self._db.quota_try_consume(
            f"vkey:{key.key_id}",
            self._today(),
            count_delta=requests,
            bytes_delta=tokens,
            max_count=key.max_requests_per_day,
            max_bytes=key.max_tokens_per_day,
        )
        return ok

    def add_usage(self, key: VirtualKey, *, tokens: int) -> None:
        self._db.quota_try_consume(
            f"vkey:{key.key_id}", self._today(), bytes_delta=tokens
        )

    def usage(self, key: VirtualKey) -> tuple[int, int]:
        """(requests, tokens) consumed in the current window."""
        return self._db.quota_usage(f"vkey:{key.key_id}", self._today())


__all__ = ["BudgetLedger", "TOKEN_PREFIX", "VirtualKey", "VirtualKeyStore"]
