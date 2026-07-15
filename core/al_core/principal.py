"""Who is calling the control plane, and what may they see (L6/RBAC seam).

Core owns the *enforcement*: every evidence endpoint scopes its
query to ``principal.org`` and checks ``principal.can(...)``. Core does not own
the *directory* — resolving a token to a principal is an injectable
``Authenticator``:

* the default here is single-tenant: the admin API token grants an ``admin``
  principal with ``org=None`` (all orgs). That is the open-core behaviour and
  needs no user store.
* the governance layer injects a multi-org authenticator backed
  by a real user directory, and every scoping rule below applies unchanged.

Splitting it this way means the isolation is enforced in the core — a
governance bug cannot *widen* what a principal sees, only narrow it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

#: Capabilities per role. The dashboard gates on capabilities, never on the
#: role name, so adding a role never means touching the UI.
CAPABILITIES: dict[str, list[str]] = {
    "admin": ["view", "verify", "approve", "configure", "attest"],
    "operator": ["view", "verify", "approve"],
    "viewer": ["view", "verify"],
}


@dataclass(frozen=True)
class Principal:
    """An authenticated caller. ``org=None`` means cross-org (fleet) scope —
    only ever granted to a single-tenant admin or a fleet admin."""

    subject: str
    role: str
    org: str | None = None

    @property
    def capabilities(self) -> list[str]:
        return CAPABILITIES.get(self.role, ["view"])

    def can(self, capability: str) -> bool:
        return capability in self.capabilities

    @property
    def scope(self) -> str | None:
        """The org filter to apply to every query for this principal."""
        return self.org


#: Resolve a request's credentials to a Principal (None = unauthenticated).
#: Takes the raw bearer token so it stays framework-agnostic.
Authenticator = Callable[[str | None], "Principal | None"]


__all__ = ["CAPABILITIES", "Authenticator", "Principal"]
