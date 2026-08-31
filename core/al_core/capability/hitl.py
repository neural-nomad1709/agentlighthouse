"""Human-in-the-loop gate (L4) — irreversible verbs pause for approval (ASI09).

Irreversible actions (send, delete, transfer, publish, deploy) do not execute
on the agent's say-so: the call is held as a pending approval that a human
resolves via the control plane. **Timeout is a denial** — an unattended
request fails closed, never open.

A **tainted** session (see :mod:`.taint`) widens the gate: protected — not just
irreversible — operations then also require approval, because a session that
ingested untrusted content can no longer be trusted to drive even normally-
allowed writes unattended.

The gate holds state (pending requests) but does not block a thread waiting:
the caller submits, returns ``HITL_REQUIRED`` to the agent, and the decision
resolves out of band. ``decision`` maps a request to allow / block at any time.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable

from ..gateway.decision import BlockReason, Decision, finding

# Verb → irreversible if the tool name starts with one of these (or is listed
# explicitly in ``extra_irreversible``). Irreversible = cannot be undone once
# it leaves the boundary.
_IRREVERSIBLE_PREFIXES = ("send", "delete", "remove", "transfer", "publish",
                          "deploy", "purchase", "pay", "wire", "email", "post")

# When a session is TAINTED, these broader protected operations also gate.
_PROTECTED_PREFIXES = _IRREVERSIBLE_PREFIXES + (
    "write", "exec", "run", "http_post", "update", "create", "modify", "put")

_PENDING = "pending"
_APPROVED = "approved"
_DENIED = "denied"


def _verb_matches(tool: str, prefixes: tuple[str, ...], explicit: frozenset[str]) -> bool:
    # Match on a word boundary (exact verb, or verb_noun) so "post" gates
    # "post_message" but not "postgres_query".
    t = tool.lower()
    return t in explicit or any(t == p or t.startswith(p + "_") for p in prefixes)


@dataclass
class ApprovalRequest:
    request_id: str
    actor: str
    tool: str
    created_at: float
    timeout_s: float
    status: str = _PENDING
    resolved_at: float | None = None
    resolved_by: str | None = None


class HitlGate:
    """Holds pending approvals; resolves them to allow/deny with timeout=deny."""

    def __init__(
        self,
        *,
        timeout_s: float = 300.0,
        extra_irreversible: tuple[str, ...] = (),
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._timeout_s = timeout_s
        self._explicit = frozenset(t.lower() for t in extra_irreversible)
        import time
        self._clock = clock or time.monotonic
        self._pending: dict[str, ApprovalRequest] = {}

    # -- classification ------------------------------------------------------

    def is_irreversible(self, tool: str) -> bool:
        return _verb_matches(tool, _IRREVERSIBLE_PREFIXES, self._explicit)

    def requires_approval(self, tool: str, *, tainted: bool = False) -> bool:
        """Irreversible always gates; a tainted session also gates protected ops."""
        if self.is_irreversible(tool):
            return True
        if tainted and _verb_matches(tool, _PROTECTED_PREFIXES, self._explicit):
            return True
        return False

    # -- request lifecycle ---------------------------------------------------

    def submit(self, actor: str, tool: str) -> ApprovalRequest:
        req = ApprovalRequest(
            request_id="hitl_" + secrets.token_hex(8),
            actor=actor, tool=tool,
            created_at=self._clock(), timeout_s=self._timeout_s,
        )
        self._pending[req.request_id] = req
        return req

    def approve(self, request_id: str, *, by: str | None = None) -> bool:
        return self._resolve(request_id, _APPROVED, by=by)

    def deny(self, request_id: str, *, by: str | None = None) -> bool:
        return self._resolve(request_id, _DENIED, by=by)

    def _resolve(self, request_id: str, status: str, *, by: str | None = None) -> bool:
        req = self._pending.get(request_id)
        if req is None or req.status != _PENDING:
            return False
        if self._timed_out(req):
            return False  # already lapsed → cannot be resolved
        req.status = status
        req.resolved_at = self._clock()
        req.resolved_by = by
        return True

    def _timed_out(self, req: ApprovalRequest) -> bool:
        return req.status == _PENDING and (self._clock() - req.created_at) >= req.timeout_s

    def age_s(self, request_id: str) -> float | None:
        """Seconds since the request was submitted (None for an unknown id)."""
        req = self._pending.get(request_id)
        return None if req is None else max(0.0, self._clock() - req.created_at)

    def remaining_s(self, request_id: str) -> float | None:
        """Seconds until the request lapses (0 once lapsed; None if unknown)."""
        req = self._pending.get(request_id)
        if req is None:
            return None
        return max(0.0, req.timeout_s - (self._clock() - req.created_at))

    def status(self, request_id: str) -> str:
        req = self._pending.get(request_id)
        if req is None:
            return "unknown"
        if req.status == _PENDING and self._timed_out(req):
            return "timed_out"
        return req.status

    def pending(self) -> list[ApprovalRequest]:
        return [r for r in self._pending.values() if self.status(r.request_id) == _PENDING]

    # -- decision mapping ----------------------------------------------------

    def decision(self, request_id: str) -> Decision:
        """Map a request's current state to a gateway Decision (fail-closed)."""
        st = self.status(request_id)
        if st == _APPROVED:
            return Decision.allow()
        if st == _PENDING:
            return Decision.block(
                BlockReason.HITL_REQUIRED,
                [finding("hitl", "hitl.awaiting_approval", "medium", owasp="ASI09")],
            )
        # denied, timed_out, unknown → deny
        rule = "hitl.timed_out" if st == "timed_out" else "hitl.denied"
        return Decision.block(
            BlockReason.HITL_DENIED,
            [finding("hitl", rule, "high", owasp="ASI09")],
        )


__all__ = ["ApprovalRequest", "HitlGate"]
