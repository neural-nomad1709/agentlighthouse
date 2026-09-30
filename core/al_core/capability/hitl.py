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

An approval is a **grant** for exactly what was asked: the actor, tool,
argument digest and session that filed the request. The agent retries the same
call; :meth:`HitlGate.claim` finds the grant and :meth:`HitlGate.consume`
spends it, once. A grant is valid for ``timeout_s`` after it was given, then it
lapses like an unanswered request. With a store attached the store is the
source of truth, so a request filed by one process and resolved by another
(data plane / control plane) behaves as if both were one gate.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Any, Callable

from typing import TYPE_CHECKING

from ..gateway.decision import BlockReason, Decision, finding

if TYPE_CHECKING:
    from .store import CapabilityStore

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
_CONSUMED = "consumed"  # grant spent: never reusable
_EXPIRED = "expired"    # grant not spent within its window
_TIMED_OUT = "timed_out"


def args_digest(args: dict[str, Any] | None) -> str:
    """Stable digest of a call's arguments: what an approval is bound to."""
    canonical = json.dumps(args or {}, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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
    #: What is actually being approved — e.g. the fully rendered commands a
    #: remote-exec host will run. Approving a bare tool name is not informed
    #: consent; every resolution surface shows this.
    detail: str | None = None
    #: The caller's session the request belongs to, so an embedder can
    #: re-associate a rehydrated request with the run that filed it.
    session: str | None = None
    #: Digest of the call's arguments (:func:`args_digest`). An approval only
    #: grants a call whose arguments hash the same.
    args_digest: str | None = None

    def binds(self, actor: str, tool: str, digest: str | None,
              session: str | None) -> bool:
        """True if the call (actor, tool, args, session) is the one requested.
        The session is bound only when both sides name one."""
        return (self.actor == actor and self.tool == tool
                and self.args_digest == digest
                and (self.session is None or session is None or self.session == session))


class HitlGate:
    """Holds pending approvals; resolves them to allow/deny with timeout=deny."""

    def __init__(
        self,
        *,
        timeout_s: float = 300.0,
        extra_irreversible: tuple[str, ...] = (),
        clock: Callable[[], float] | None = None,
        store: "CapabilityStore | None" = None,
    ) -> None:
        self._timeout_s = timeout_s
        self._explicit = frozenset(t.lower() for t in extra_irreversible)
        import time
        self._clock = clock or time.monotonic
        self._pending: dict[str, ApprovalRequest] = {}
        self._store = store
        if store is not None:
            # Rehydrate every live request, so an unspent grant is still found
            # by the call it was filed for. The store keeps wall-clock ages;
            # re-anchor each in THIS process's clock preserving elapsed age, so
            # the original deadline is enforced. The store drops lapsed and
            # from-the-future rows itself (fail closed). Later resolutions are
            # read through on demand (``_sync``).
            for row in store.live_approvals():
                self._adopt(row)

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

    def submit(
        self, actor: str, tool: str, *,
        detail: str | None = None, session: str | None = None,
        args: dict[str, Any] | None = None,
    ) -> ApprovalRequest:
        self._evict_final()
        req = ApprovalRequest(
            request_id="hitl_" + secrets.token_hex(8),
            actor=actor, tool=tool,
            created_at=self._clock(), timeout_s=self._timeout_s,
            detail=detail, session=session, args_digest=args_digest(args),
        )
        self._pending[req.request_id] = req
        if self._store is not None:
            self._store.save_approval(req.request_id, actor, tool, req.timeout_s,
                                      detail=detail, session=session,
                                      args_digest=req.args_digest)
        return req

    def approve(self, request_id: str, *, by: str | None = None) -> bool:
        return self._resolve(request_id, _APPROVED, by=by)

    def deny(self, request_id: str, *, by: str | None = None) -> bool:
        return self._resolve(request_id, _DENIED, by=by)

    def _resolve(self, request_id: str, status: str, *, by: str | None = None) -> bool:
        req = self._sync(request_id)
        if req is None or req.status != _PENDING:
            return False
        if self._timed_out(req):
            return False  # already lapsed → cannot be resolved
        if self._store is not None and not self._store.resolve_approval(
                request_id, status, by):
            self._sync(request_id)  # another process resolved it first
            return False
        req.status = status
        req.resolved_at = self._clock()
        req.resolved_by = by
        return True

    def claim(
        self, actor: str, tool: str, args: dict[str, Any] | None, *,
        session: str | None, request_id: str | None = None,
    ) -> ApprovalRequest | None:
        """The live request covering this exact call, if any: an approved one
        first, then a pending one. A request the agent names explicitly is also
        returned once finally denied, so the agent learns the answer. Does not
        spend a grant (:meth:`consume` does). A named request that does not
        bind to this call is ignored: an id never widens what was approved."""
        digest = args_digest(args)
        if request_id is not None:
            req = self._sync(request_id)
            if (req is not None and req.binds(actor, tool, digest, session)
                    and self.status(request_id) in (_APPROVED, _PENDING, _DENIED, _TIMED_OUT)):
                return req
        matching = [r for r in list(self._pending.values())
                    if r.binds(actor, tool, digest, session)]
        for wanted in (_APPROVED, _PENDING):
            for r in matching:
                if self.status(r.request_id) == wanted:
                    return r
        return None

    def consume(self, request_id: str, actor: str, tool: str,
                args: dict[str, Any] | None, *, session: str | None) -> bool:
        """Spend an approval grant on this exact call. True at most once per
        grant, across every process sharing the store."""
        req = self._sync(request_id)
        if req is None or self.status(request_id) != _APPROVED:
            return False
        if not req.binds(actor, tool, args_digest(args), session):
            return False
        if self._store is not None and not self._store.consume_approval(request_id):
            req.status = _CONSUMED  # spent elsewhere, or lapsed in the store
            return False
        req.status = _CONSUMED
        return True

    def _sync(self, request_id: str) -> ApprovalRequest | None:
        """Refresh one request from the store, the cross-process truth."""
        req = self._pending.get(request_id)
        if self._store is None:
            return req
        row = self._store.approval(request_id)
        if row is None:
            # Gone from the store: spent by another process, or pruned after
            # its window. Either way an approval here can no longer be used.
            if req is not None and req.status == _APPROVED:
                req.status = _CONSUMED
            return req
        if req is None:
            return self._adopt(row)
        if req.status == _PENDING and row["status"] != _PENDING:
            self._apply_resolution(req, row)
        return req

    def _adopt(self, row: dict) -> ApprovalRequest:
        """Materialize a store row in this process's clock, elapsed age kept."""
        req = ApprovalRequest(
            request_id=row["request_id"], actor=row["actor"], tool=row["tool"],
            created_at=self._clock() - row["age_s"], timeout_s=row["timeout_s"],
            detail=row["detail"], session=row["session"],
            args_digest=row["args_digest"],
        )
        if row["status"] != _PENDING:
            self._apply_resolution(req, row)
        self._pending[req.request_id] = req
        return req

    def _apply_resolution(self, req: ApprovalRequest, row: dict) -> None:
        req.status = row["status"]
        req.resolved_by = row["resolved_by"]
        req.resolved_at = self._clock() - row["resolved_age_s"]

    def _evict_final(self) -> None:
        """Forget requests two windows old. By then each is final whatever
        happened (pending timed out one window in; a grant lasts one window
        from approval, which came within the first), so its decision is a deny
        with or without it, and memory stays bounded by the filing rate. The
        store, when there is one, stays the cross-process truth."""
        now = self._clock()
        for rid, req in list(self._pending.items()):
            if now - req.created_at >= 2 * req.timeout_s:
                del self._pending[rid]

    def _timed_out(self, req: ApprovalRequest) -> bool:
        return req.status == _PENDING and (self._clock() - req.created_at) >= req.timeout_s

    def _grant_expired(self, req: ApprovalRequest) -> bool:
        return (req.status == _APPROVED and req.resolved_at is not None
                and (self._clock() - req.resolved_at) >= req.timeout_s)

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

    def request(self, request_id: str) -> ApprovalRequest | None:
        """The request itself, resolved or not (None for an unknown id)."""
        return self._sync(request_id)

    def status(self, request_id: str) -> str:
        req = self._sync(request_id)
        if req is None:
            return "unknown"
        if self._timed_out(req):
            return _TIMED_OUT
        if self._grant_expired(req):
            return _EXPIRED
        return req.status

    def pending(self) -> list[ApprovalRequest]:
        if self._store is not None:
            for row in self._store.load_approvals():  # filed by any process
                self._sync(row["request_id"])
        return [r for r in list(self._pending.values())
                if r.status == _PENDING and self.status(r.request_id) == _PENDING]

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
        # denied, timed_out, consumed, expired, unknown → deny
        rule = {_TIMED_OUT: "hitl.timed_out", _CONSUMED: "hitl.grant_consumed",
                _EXPIRED: "hitl.grant_expired"}.get(st, "hitl.denied")
        return Decision.block(
            BlockReason.HITL_DENIED,
            [finding("hitl", rule, "high", owasp="ASI09")],
        )


__all__ = ["ApprovalRequest", "HitlGate", "args_digest"]
