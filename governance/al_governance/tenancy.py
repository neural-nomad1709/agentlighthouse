"""Org + user directory (multi-tenant RBAC).

The core plane enforces isolation; this module is the *directory* it enforces
against — orgs, their users, each user's role, and the token that authenticates
them. Tokens are stored **hashed** (SHA-256) and shown exactly once at issue,
like the Phase-1 virtual keys: a stolen store yields no usable credential.

Roles come from the core capability table (admin / operator / viewer) so the
dashboard's capability gating needs no governance-specific knowledge.

An org's users are bound to that org: authenticating returns a Principal whose
``org`` is the user's own, and core scopes every query to it. A **fleet admin**
(``org=None``, created with ``--fleet``) is the only principal that sees across
orgs — that is a deliberate, auditable escalation, not a default.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path

from al_core.principal import CAPABILITIES, Principal
from al_core.receipt import utcnow_iso

TOKEN_PREFIX = "alg_"  # governance user token (cf. alk_ virtual keys)


def hash_token(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class User:
    subject: str          # "alice@acme"
    org: str | None       # None = fleet scope (cross-org admin)
    role: str             # admin | operator | viewer
    token_hash: str
    created_ts: str

    def principal(self) -> Principal:
        return Principal(subject=self.subject, role=self.role, org=self.org)


@dataclass(frozen=True)
class Issued:
    user: User
    token: str  # shown once, never stored


class OrgStore:
    """Orgs + users, persisted as JSON. Small by design: a directory, not a DB."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._orgs: dict[str, dict] = {}
        self._users: dict[str, User] = {}
        if self._path.exists():
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            self._orgs = raw.get("orgs", {})
            self._users = {k: User(**v) for k, v in raw.get("users", {}).items()}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps({
            "orgs": dict(sorted(self._orgs.items())),
            "users": {k: asdict(u) for k, u in sorted(self._users.items())},
        }, indent=2), encoding="utf-8")

    # -- orgs ------------------------------------------------------------------

    def create_org(self, org: str, *, display_name: str | None = None) -> dict:
        if org in self._orgs:
            raise ValueError(f"org already exists: {org}")
        if org == "system":
            raise ValueError("'system' is reserved (non-agent actors)")
        self._orgs[org] = {"org": org, "display_name": display_name or org,
                           "created_ts": utcnow_iso()}
        self._save()
        return self._orgs[org]

    def orgs(self) -> list[dict]:
        return [self._orgs[k] for k in sorted(self._orgs)]

    def has_org(self, org: str) -> bool:
        return org in self._orgs

    # -- users -----------------------------------------------------------------

    def add_user(self, subject: str, *, org: str | None, role: str) -> Issued:
        """Create a user and issue its token (returned once, stored hashed)."""
        if role not in CAPABILITIES:
            raise ValueError(f"unknown role: {role} (want {', '.join(CAPABILITIES)})")
        if subject in self._users:
            raise ValueError(f"user already exists: {subject}")
        if org is not None and org not in self._orgs:
            raise ValueError(f"no such org: {org} — create it first")
        if org is None and role != "admin":
            raise ValueError("fleet scope (org=None) is admin-only")
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        user = User(subject=subject, org=org, role=role,
                    token_hash=hash_token(token), created_ts=utcnow_iso())
        self._users[subject] = user
        self._save()
        return Issued(user=user, token=token)

    def users(self, org: str | None = None) -> list[User]:
        out = [u for u in self._users.values() if org is None or u.org == org]
        return sorted(out, key=lambda u: (u.org or "", u.subject))

    def revoke(self, subject: str) -> bool:
        if self._users.pop(subject, None) is None:
            return False
        self._save()
        return True

    # -- authentication ----------------------------------------------------------

    def authenticate(self, token: str | None) -> Principal | None:
        """Token -> Principal. Constant-time compare against the stored hashes;
        an unknown token is indistinguishable from a wrong one."""
        if not token or not token.startswith(TOKEN_PREFIX):
            return None
        presented = hash_token(token)
        for user in self._users.values():
            if secrets.compare_digest(user.token_hash, presented):
                return user.principal()
        return None


__all__ = ["Issued", "OrgStore", "TOKEN_PREFIX", "User", "hash_token"]
