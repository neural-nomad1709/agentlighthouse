"""Per-org budgets + cost tracking.

Phase 1 gave every *virtual key* a daily request/token budget. Governance adds
the tier above it: an **org-wide** daily budget, so one runaway agent cannot
spend the whole tenant's allowance, plus a cost view an operator can bill from.

Both ride the Phase-0 quotas table (atomic check-and-increment, UTC-day
rollover) — no new storage, and the same fail-closed semantics: over budget is
a denial, never a warning.

**Cost is derived, never invented.** Receipts deliberately carry no token
counts (the evidence schema is counts-and-classes only), so spend is read from
the quotas table the reverse proxy already writes: per-virtual-key requests and
tokens for the current UTC day, attributed to an org through the key's actor.
Pricing needs a rate the operator supplies; without one the report says
``usd: null`` rather than quietly billing zero — an unknown price is not free.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Any, Callable

from al_core.audit.db import SqliteMirror, org_of
from al_core.gateway.decision import BlockReason
from al_core.gateway.vkeys import BudgetLedger, VirtualKeyStore


def utc_today() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")


@dataclass(frozen=True)
class OrgBudget:
    org: str
    max_requests_per_day: int | None = None
    max_tokens_per_day: int | None = None


class OrgBudgetLedger:
    """Org-scoped daily budgets on the shared quotas table.

    Same contract as the per-key ``BudgetLedger`` it sits above: ``try_request``
    is the atomic pre-flight gate; ``record_usage`` records post-hoc tokens
    unconditionally (usage that already happened is never dropped — the *next*
    pre-flight denies)."""

    def __init__(self, db: SqliteMirror, budgets: dict[str, OrgBudget] | None = None,
                 *, today: Callable[[], str] | None = None) -> None:
        self._db = db
        self._budgets = budgets or {}
        self._today = today or utc_today

    def budget(self, org: str) -> OrgBudget | None:
        return self._budgets.get(org)

    def try_request(self, org: str, tokens: int = 0) -> tuple[bool, str | None]:
        """Atomically charge one request (+ tokens) against the org's day.

        Returns (allowed, block_reason). An org with no budget is allowed — a
        budget is a limit the operator opts into, not a default deny (the tool
        policy is the default-deny surface; this is denial-of-wallet control)."""
        b = self._budgets.get(org)
        if b is None:
            return True, None
        ok, _, _ = self._db.quota_try_consume(
            f"org:{org}", self._today(),
            count_delta=1, bytes_delta=tokens,
            max_count=b.max_requests_per_day, max_bytes=b.max_tokens_per_day,
        )
        return (True, None) if ok else (False, BlockReason.BUDGET_EXCEEDED)

    def record_usage(self, org: str, tokens: int) -> None:
        """Post-hoc token accounting (streamed replies count after the fact)."""
        self._db.quota_try_consume(f"org:{org}", self._today(), bytes_delta=tokens)

    def usage(self, org: str) -> tuple[int, int]:
        """(requests, tokens) consumed by the org in the current UTC day."""
        return self._db.quota_usage(f"org:{org}", self._today())


def cost_report(
    db: SqliteMirror,
    vkeys: VirtualKeyStore,
    *,
    org: str | None = None,
    usd_per_mtok: float | None = None,
) -> dict[str, Any]:
    """Today's spend for an org (or the fleet), from the quotas table.

    ``usd_per_mtok`` is the operator's blended rate. Receipts carry no model
    attribution (``llm_call`` targets are provider+path), so this reports a
    blended figure honestly rather than fabricating a per-model split. Omit the
    rate and ``usd`` is ``None``.
    """
    budgets = BudgetLedger(db)
    keys = []
    total_requests = total_tokens = 0
    for key in vkeys.list():
        key_org = org_of(key.actor)
        if org is not None and key_org != org:
            continue
        requests, tokens = budgets.usage(key)
        total_requests += requests
        total_tokens += tokens
        keys.append({
            "key_id": key.key_id,
            "actor": key.actor,
            "org": key_org,
            "requests": requests,
            "tokens": tokens,
            "disabled": key.disabled,
        })

    usd = (round(total_tokens * usd_per_mtok / 1_000_000, 6)
           if usd_per_mtok is not None else None)
    return {
        "org": org,
        "day": utc_today(),
        "keys": sorted(keys, key=lambda k: -k["tokens"]),
        "total_requests": total_requests,
        "total_tokens": total_tokens,
        "usd": usd,
        "rate_usd_per_mtok": usd_per_mtok,
    }


__all__ = ["OrgBudget", "OrgBudgetLedger", "cost_report", "utc_today"]
