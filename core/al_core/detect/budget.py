"""Per-domain rate limit + data budget — the denial-of-wallet / loop-storm
guard (ASI08). Stateful and keyed off the *destination domain*, so it is not
a text ``Scanner`` — the gateway calls it with (domain, response_bytes) around
each egress, and it rides the same SQLite ``quotas`` table as virtual-key
budgets (operational state, not evidence).

Two independent windows per domain:

* **rate** — requests per second (``per_domain_rps``); window = the integer
  UTC second, so it self-rolls without a cleanup job.
* **data** — bytes per UTC day (``per_domain_bytes``); window = ``YYYY-MM-DD``.

Both use the atomic check-and-increment on the mirror. A pre-flight
``try_request`` reserves one request slot (rate); ``try_data`` charges bytes
after a response arrives — usage that already happened is never dropped, but
going over budget denies the *next* call (matches the vkey budget contract).
"""

from __future__ import annotations

import datetime as _dt
from typing import Callable
from urllib.parse import urlsplit

from ..audit.db import SqliteMirror
from ..gateway.decision import BlockReason


def domain_of(url_or_host: str) -> str:
    """Registrable-ish domain key: the lowercased host, port stripped. Good
    enough for per-destination budgeting (we key on the exact host, so
    ``a.example.com`` and ``b.example.com`` budget separately — intentional:
    subdomain fan-out is a tunneling signal, not a shared pool)."""
    host = url_or_host
    if "://" in url_or_host:
        host = urlsplit(url_or_host).hostname or url_or_host
    host = host.strip("[]").lower()
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def _utc_second() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _utc_day() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")


class RateBudgetLedger:
    def __init__(
        self,
        db: SqliteMirror,
        *,
        per_domain_rps: int,
        per_domain_bytes: int,
        second: Callable[[], str] | None = None,
        day: Callable[[], str] | None = None,
    ) -> None:
        self._db = db
        self._rps = per_domain_rps
        self._max_bytes = per_domain_bytes
        self._second = second or _utc_second
        self._day = day or _utc_day

    def try_request(self, domain: str) -> tuple[bool, str | None]:
        """Reserve one request slot this second. Returns (ok, block_reason)."""
        ok, _, _ = self._db.quota_try_consume(
            f"rate:{domain}", self._second(),
            count_delta=1, max_count=self._rps,
        )
        return (True, None) if ok else (False, BlockReason.RATE_LIMIT_EXCEEDED)

    def try_data(self, domain: str, nbytes: int) -> tuple[bool, str | None]:
        """Charge ``nbytes`` against today's per-domain byte budget."""
        ok, _, _ = self._db.quota_try_consume(
            f"data:{domain}", self._day(),
            bytes_delta=nbytes, max_bytes=self._max_bytes,
        )
        return (True, None) if ok else (False, BlockReason.DATA_BUDGET_EXCEEDED)

    def charge_data(self, domain: str, nbytes: int) -> None:
        """Record bytes unconditionally (post-hoc; never dropped)."""
        self._db.quota_try_consume(f"data:{domain}", self._day(), bytes_delta=nbytes)

    def usage(self, domain: str) -> tuple[int, int]:
        """(requests_this_second, bytes_today) for observability/tests."""
        reqs, _ = self._db.quota_usage(f"rate:{domain}", self._second())
        _, byts = self._db.quota_usage(f"data:{domain}", self._day())
        return reqs, byts


__all__ = ["RateBudgetLedger", "domain_of"]
