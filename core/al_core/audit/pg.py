"""Postgres mirror — the concurrent-writer path (Phase 6).

Same contract as :class:`~al_core.audit.db.SqliteMirror`: a **query surface**,
never a source of truth (the append-only JSONL stays canonical). The reason it
exists is concurrency, not scale:

* SQLite serializes writers behind one process-local lock. That is fine for one
  mediator, and it is exactly what a multi-writer deployment cannot rely on —
  two al-core replicas sharing a mirror would race the ``quotas`` table, and a
  raced budget check is a **denial-of-wallet hole**: both writers read "99 of
  100 used", both allow, and the tenant spends 101.
* Postgres gives us a real lock. ``quota_try_consume`` materializes the row,
  takes ``SELECT ... FOR UPDATE`` on it, and only then decides — so N writers
  hitting one budget concurrently allow *exactly* the budget, never one more.

Requires the ``postgres`` extra (``psycopg[binary]``). Import stays lazy so a
SQLite-only deployment never pays for it.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Iterator

from .db import org_of

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq          BIGINT PRIMARY KEY,
    ts           TEXT NOT NULL,
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    target       TEXT NOT NULL,
    verdict      TEXT NOT NULL,
    block_reason TEXT,
    prev_hash    TEXT NOT NULL,
    record_hash  TEXT NOT NULL,
    receipt_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_actor   ON events(actor);
CREATE INDEX IF NOT EXISTS idx_events_action  ON events(action);
CREATE INDEX IF NOT EXISTS idx_events_verdict ON events(verdict);

CREATE TABLE IF NOT EXISTS quotas (
    quota_key    TEXT PRIMARY KEY,
    window_start TEXT NOT NULL,
    count        BIGINT NOT NULL DEFAULT 0,
    bytes        BIGINT NOT NULL DEFAULT 0
);
"""


def _org_filter(org: str | None) -> tuple[list[str], list[Any]]:
    if org is None:
        return [], []
    if org == "system":
        return ["actor NOT LIKE 'spiffe://%%'"], []
    return ["actor LIKE %s"], [f"spiffe://{org}/%"]


class PostgresMirror:
    """Multi-writer mirror. Method-for-method compatible with SqliteMirror for
    everything the control plane and governance layer read."""

    def __init__(self, dsn: str) -> None:
        import psycopg  # lazy: only a postgres deployment needs the driver

        self._psycopg = psycopg
        self._dsn = dsn
        self._conn = psycopg.connect(dsn, autocommit=True)
        with self._conn.cursor() as cur:
            cur.execute(_SCHEMA)

    # -- writes ---------------------------------------------------------------

    def upsert_event(self, receipt: dict[str, Any]) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO events (seq, ts, actor, action, target, verdict, "
                " block_reason, prev_hash, record_hash, receipt_json) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (seq) DO UPDATE SET "
                " ts=EXCLUDED.ts, actor=EXCLUDED.actor, action=EXCLUDED.action, "
                " target=EXCLUDED.target, verdict=EXCLUDED.verdict, "
                " block_reason=EXCLUDED.block_reason, prev_hash=EXCLUDED.prev_hash, "
                " record_hash=EXCLUDED.record_hash, receipt_json=EXCLUDED.receipt_json",
                (receipt["seq"], receipt["ts"], receipt["actor"], receipt["action"],
                 receipt["target"], receipt["verdict"], receipt.get("block_reason"),
                 receipt["prev_hash"], receipt["record_hash"],
                 json.dumps(receipt, separators=(",", ":"), ensure_ascii=False)),
            )

    def reconcile(self, receipts: Iterable[dict[str, Any]]) -> int:
        n = 0
        for r in receipts:
            self.upsert_event(r)
            n += 1
        return n

    # -- quotas (THE reason this backend exists) --------------------------------

    def quota_try_consume(
        self,
        quota_key: str,
        window_start: str,
        *,
        count_delta: int = 0,
        bytes_delta: int = 0,
        max_count: int | None = None,
        max_bytes: int | None = None,
    ) -> tuple[bool, int, int]:
        """Atomic check-and-increment across *processes*.

        The row is materialized, then locked with ``FOR UPDATE`` for the whole
        decide-and-write. Concurrent writers therefore queue on the row rather
        than racing it: a budget of N admits exactly N, never N+1.
        """
        with self._conn.transaction(), self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO quotas (quota_key, window_start, count, bytes) "
                "VALUES (%s, %s, 0, 0) ON CONFLICT (quota_key) DO NOTHING",
                (quota_key, window_start),
            )
            cur.execute(
                "SELECT window_start, count, bytes FROM quotas "
                "WHERE quota_key=%s FOR UPDATE",
                (quota_key,),
            )
            row = cur.fetchone()
            in_window = row is not None and row[0] == window_start
            cur_count = row[1] if in_window else 0
            cur_bytes = row[2] if in_window else 0
            new_count, new_bytes = cur_count + count_delta, cur_bytes + bytes_delta
            if (max_count is not None and new_count > max_count) or (
                max_bytes is not None and new_bytes > max_bytes
            ):
                return False, cur_count, cur_bytes
            cur.execute(
                "UPDATE quotas SET window_start=%s, count=%s, bytes=%s "
                "WHERE quota_key=%s",
                (window_start, new_count, new_bytes, quota_key),
            )
            return True, new_count, new_bytes

    def quota_usage(self, quota_key: str, window_start: str) -> tuple[int, int]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT window_start, count, bytes FROM quotas WHERE quota_key=%s",
                (quota_key,),
            )
            row = cur.fetchone()
        if row is None or row[0] != window_start:
            return 0, 0
        return int(row[1]), int(row[2])

    # -- reads (same surface + same org scoping as SQLite) ----------------------

    def _rows(self, sql: str, params: list[Any]) -> list[Any]:
        with self._conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchall()

    def count_events(self, org: str | None = None) -> int:
        clauses, params = _org_filter(org)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return int(self._rows(f"SELECT COUNT(*) FROM events {where}", params)[0][0])

    def latest_seq(self) -> int | None:
        row = self._rows("SELECT MAX(seq) FROM events", [])[0][0]
        return int(row) if row is not None else None

    def last_config_hash(self) -> str | None:
        rows = self._rows(
            "SELECT receipt_json FROM events WHERE action='config_change' "
            "ORDER BY seq DESC LIMIT 1", [])
        return json.loads(rows[0][0]).get("policy_hash") if rows else None

    def _group_count(self, column: str, extra: str = "",
                     org: str | None = None) -> dict[str, int]:
        clauses, params = _org_filter(org)
        if extra:
            clauses.append(extra)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self._rows(
            f"SELECT {column}, COUNT(*) FROM events {where} "
            f"GROUP BY {column} ORDER BY 2 DESC", params)
        return {r[0]: int(r[1]) for r in rows}

    def verdict_counts(self, org: str | None = None) -> dict[str, int]:
        return self._group_count("verdict", org=org)

    def action_counts(self, org: str | None = None) -> dict[str, int]:
        return self._group_count("action", org=org)

    def block_reason_counts(self, org: str | None = None) -> dict[str, int]:
        return self._group_count("block_reason", "block_reason IS NOT NULL", org=org)

    def actor_counts(self, org: str | None = None) -> dict[str, int]:
        return self._group_count("actor", org=org)

    def org_counts(self, org: str | None = None) -> dict[str, int]:
        out: dict[str, int] = {}
        for actor, n in self.actor_counts(org).items():
            out[org_of(actor)] = out.get(org_of(actor), 0) + n
        return out

    def recent_filtered(
        self, *, limit: int = 50, actor: str | None = None, action: str | None = None,
        verdict: str | None = None, org: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses, params = _org_filter(org)
        for col, val in (("actor", actor), ("action", action), ("verdict", verdict)):
            if val is not None:
                clauses.append(f"{col}=%s")
                params.append(val)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(max(1, min(limit, 500)))
        rows = self._rows(
            f"SELECT receipt_json FROM events {where} ORDER BY seq DESC LIMIT %s", params)
        return [json.loads(r[0]) for r in rows]

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.recent_filtered(limit=limit)

    def receipt_by_seq(self, seq: int, org: str | None = None) -> dict[str, Any] | None:
        clauses, params = _org_filter(org)
        clauses.append("seq=%s")
        params.append(seq)
        rows = self._rows(
            "SELECT receipt_json FROM events WHERE " + " AND ".join(clauses), params)
        return json.loads(rows[0][0]) if rows else None

    def search(
        self, *, query: str | None = None, since: str | None = None,
        until: str | None = None, actor: str | None = None, action: str | None = None,
        verdict: str | None = None, org: str | None = None, limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses, params = _org_filter(org)
        for col, val in (("actor", actor), ("action", action), ("verdict", verdict)):
            if val is not None:
                clauses.append(f"{col}=%s")
                params.append(val)
        if since is not None:
            clauses.append("ts >= %s")
            params.append(since)
        if until is not None:
            clauses.append("ts <= %s")
            params.append(until)
        if query:
            clauses.append("(actor ILIKE %s OR target ILIKE %s "
                           "OR COALESCE(block_reason,'') ILIKE %s)")
            like = f"%{query}%"
            params.extend([like, like, like])
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(max(1, min(limit, 500)))
        rows = self._rows(
            f"SELECT receipt_json FROM events {where} ORDER BY seq DESC LIMIT %s", params)
        return [json.loads(r[0]) for r in rows]

    def iter_receipts(
        self, *, since: str | None = None, until: str | None = None,
        org: str | None = None, batch: int = 1000,
    ) -> Iterator[dict[str, Any]]:
        """Every receipt in the window, newest first — uncapped (see the
        SQLite twin): keyset-paginated on ``seq``."""
        base, base_params = _org_filter(org)
        if since is not None:
            base.append("ts >= %s")
            base_params.append(since)
        if until is not None:
            base.append("ts <= %s")
            base_params.append(until)
        last_seq: int | None = None
        while True:
            clauses, params = list(base), list(base_params)
            if last_seq is not None:
                clauses.append("seq < %s")
                params.append(last_seq)
            where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
            params.append(max(1, batch))
            rows = self._rows(
                f"SELECT seq, receipt_json FROM events {where} "
                "ORDER BY seq DESC LIMIT %s", params)
            if not rows:
                return
            for r in rows:
                yield json.loads(r[1])
            last_seq = rows[-1][0]

    def time_series(self, *, buckets: int = 24, span_hours: int = 24,
                    now: str | None = None, org: str | None = None) -> list[dict[str, Any]]:
        from datetime import datetime, timedelta

        clauses, params = _org_filter(org)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        if now is None:
            row = self._rows(f"SELECT MAX(ts) FROM events {where}", params)[0][0]
            now = row if row else None
        if now is None:
            return []

        def parse(s: str) -> datetime:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))

        end = parse(now)
        start = end - timedelta(hours=span_hours)
        rows = self._rows(
            f"SELECT ts, verdict FROM events {where}", params)
        width = (end - start) / buckets
        series = [{"bucket_start": (start + width * i).isoformat().replace("+00:00", "Z"),
                   "total": 0, "allow": 0, "block": 0, "strip": 0, "warn": 0, "ask": 0}
                  for i in range(buckets)]
        for ts, verdict in rows:
            try:
                point = parse(ts)
            except ValueError:
                continue
            if point < start or point > end:
                continue
            idx = max(0, min(buckets - 1, int((point - start) / width)))
            series[idx]["total"] += 1
            if verdict in series[idx]:
                series[idx][verdict] += 1
        return series

    def stats(self, org: str | None = None) -> dict[str, Any]:
        return {
            "events": self.count_events(org),
            "latest_seq": self.latest_seq(),
            "verdicts": self.verdict_counts(org),
            "actions": self.action_counts(org),
            "block_reasons": self.block_reason_counts(org),
            "actors": self.actor_counts(org),
            "orgs": self.org_counts(org),
        }

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "PostgresMirror":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


__all__ = ["PostgresMirror"]
