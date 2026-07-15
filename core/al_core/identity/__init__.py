"""SPIFFE-style agent identity registry (Phase-0 plumbing for the moat).

Every agent carries a real identity ``spiffe://<org>/agent/<name>``. Identity is
the through-line of the whole product (D1 / OWASP "least agency"): receipts bind
to it and least-privilege policy is keyed on it. The hard invariant is
**no identity -> deny**, so the registry's most important job is to answer
"is this a known, authenticated agent?" honestly and fail closed when unsure.

Phase 0 is plumbing: a JSON-file-backed registry that issues an identity plus a
per-agent Ed25519 keypair and a bearer token (stored only as a SHA-256 hash).
The store is swappable; a SQLite-backed store arrives when the mirror DB is wired.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..keys import public_key_hex
from ..receipt import utcnow_iso

# spiffe://<org>/agent/<name> — org and name are DNS/label-ish tokens.
_SPIFFE_RE = re.compile(r"^spiffe://(?P<org>[a-z0-9][a-z0-9._-]*)/agent/(?P<name>[a-z0-9][a-z0-9._-]*)$")


class IdentityError(Exception):
    """Base class for identity failures (fail-closed)."""


class InvalidSpiffeId(IdentityError):
    pass


class DuplicateIdentity(IdentityError):
    pass


def spiffe_id(org: str, name: str) -> str:
    sid = f"spiffe://{org}/agent/{name}"
    if not _SPIFFE_RE.match(sid):
        raise InvalidSpiffeId(f"invalid org/name for spiffe id: {org!r}/{name!r}")
    return sid


def parse_spiffe(sid: str) -> tuple[str, str]:
    m = _SPIFFE_RE.match(sid)
    if not m:
        raise InvalidSpiffeId(f"not a valid agent spiffe id: {sid!r}")
    return m.group("org"), m.group("name")


def _hash_token(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AgentIdentity:
    spiffe_id: str
    org: str
    name: str
    public_key_hex: str
    token_hash: str
    created_ts: str

    def to_json(self) -> dict:
        return {
            "spiffe_id": self.spiffe_id,
            "org": self.org,
            "name": self.name,
            "public_key_hex": self.public_key_hex,
            "token_hash": self.token_hash,
            "created_ts": self.created_ts,
        }

    @classmethod
    def from_json(cls, d: dict) -> "AgentIdentity":
        return cls(
            spiffe_id=d["spiffe_id"],
            org=d["org"],
            name=d["name"],
            public_key_hex=d["public_key_hex"],
            token_hash=d["token_hash"],
            created_ts=d["created_ts"],
        )


@dataclass(frozen=True)
class IssuedCredentials:
    """Returned once at issuance. The private key and token are NOT persisted."""

    identity: AgentIdentity
    private_key: Ed25519PrivateKey
    token: str


class IdentityRegistry:
    """In-memory registry with optional JSON-file persistence."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path else None
        self._by_id: dict[str, AgentIdentity] = {}
        if self._path and self._path.exists():
            self._load()

    def _load(self) -> None:
        assert self._path is not None
        for d in json.loads(self._path.read_text(encoding="utf-8")):
            ident = AgentIdentity.from_json(d)
            self._by_id[ident.spiffe_id] = ident

    def _save(self) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps([i.to_json() for i in self._by_id.values()], indent=2),
            encoding="utf-8",
        )

    def issue(self, org: str, name: str) -> IssuedCredentials:
        """Register a new agent: mint identity + per-agent keypair + bearer token."""
        sid = spiffe_id(org, name)
        if sid in self._by_id:
            raise DuplicateIdentity(f"identity already registered: {sid}")
        private_key = Ed25519PrivateKey.generate()
        token = secrets.token_urlsafe(32)
        ident = AgentIdentity(
            spiffe_id=sid,
            org=org,
            name=name,
            public_key_hex=public_key_hex(private_key.public_key()),
            token_hash=_hash_token(token),
            created_ts=utcnow_iso(),
        )
        self._by_id[sid] = ident
        self._save()
        return IssuedCredentials(identity=ident, private_key=private_key, token=token)

    def get(self, sid: str) -> AgentIdentity | None:
        return self._by_id.get(sid)

    def list(self) -> list[AgentIdentity]:
        return list(self._by_id.values())

    def authenticate(self, sid: str | None, token: str | None) -> AgentIdentity | None:
        """Return the identity iff sid is known AND the token matches.

        Fail-closed: any missing/mismatched input returns ``None`` (the caller
        denies). Token comparison is constant-time.
        """
        if not sid or not token:
            return None
        ident = self._by_id.get(sid)
        if ident is None:
            return None
        if not secrets.compare_digest(ident.token_hash, _hash_token(token)):
            return None
        return ident


__all__ = [
    "AgentIdentity",
    "DuplicateIdentity",
    "IdentityError",
    "IdentityRegistry",
    "InvalidSpiffeId",
    "IssuedCredentials",
    "parse_spiffe",
    "spiffe_id",
]
