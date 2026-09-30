"""SQLite (WAL) mirror of the receipt ledger — query surface only.

**This is a mirror, never a source of truth** (invariant #7). The append-only
JSONL is canonical; on startup the mirror is rebuilt/reconciled from it. Nothing
reads a security decision back out of SQLite — it exists so operators and the
dashboard can query without parsing JSONL.

The mediator serves requests from a thread pool, so the single connection is
opened with ``check_same_thread=False`` and every access is guarded by a lock.
Writes are infrequent (one per decision), so contention is negligible.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable, Iterator

def org_of(actor: str) -> str:
    """Tenancy key from a receipt actor. ``spiffe://<org>/agent/<name>`` -> org;
    everything else (``user:...``, mediator) -> ``system``. Phase-6 isolation
    filters on this."""
    if actor.startswith("spiffe://"):
        rest = actor[len("spiffe://"):]
        return rest.split("/", 1)[0] or "system"
    return "system"


def _org_filter(org: str | None) -> tuple[list[str], list[Any]]:
    """SQL clause + params scoping a query to one tenant (None = all orgs).

    Every read path takes this: an operator scoped to an org must not be able
    to reach another org's events through *any* endpoint — aggregates and
    single-receipt lookups included, not just search."""
    if org is None:
        return [], []
    if org == "system":  # non-spiffe actors (mediator, console users)
        return ["actor NOT LIKE 'spiffe://%'"], []
    return ["actor LIKE ?"], [f"spiffe://{org}/%"]


_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq          INTEGER PRIMARY KEY,
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

CREATE TABLE IF NOT EXISTS identities (
    spiffe_id      TEXT PRIMARY KEY,
    org            TEXT NOT NULL,
    name           TEXT NOT NULL,
    public_key_hex TEXT NOT NULL,
    token_hash     TEXT NOT NULL,
    created_ts     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quotas (
    quota_key    TEXT PRIMARY KEY,
    window_start TEXT NOT NULL,
    count        INTEGER NOT NULL DEFAULT 0,
    bytes        INTEGER NOT NULL DEFAULT 0
);
"""

_INSERT_EVENT = """
INSERT INTO events (seq, ts, actor, action, target, verdict,
                    block_reason, prev_hash, record_hash, receipt_json)
VALUES (:seq, :ts, :actor, :action, :target, :verdict,
        :block_reason, :prev_hash, :record_hash, :receipt_json)
ON CONFLICT(seq) DO UPDATE SET
    ts=excluded.ts, actor=excluded.actor, action=excluded.action,
    target=excluded.target, verdict=excluded.verdict,
    block_reason=excluded.block_reason, prev_hash=excluded.prev_hash,
    record_hash=excluded.record_hash, receipt_json=excluded.receipt_json
"""

_INSERT_IDENTITY = """
INSERT INTO identities (spiffe_id, org, name, public_key_hex, token_hash, created_ts)
VALUES (:spiffe_id, :org, :name, :public_key_hex, :token_hash, :created_ts)
ON CONFLICT(spiffe_id) DO UPDATE SET
    org=excluded.org, name=excluded.name,
    public_key_hex=excluded.public_key_hex,
    token_hash=excluded.token_hash, created_ts=excluded.created_ts
"""


class SqliteMirror:
    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        """``read_only=True`` opens another process's live mirror for queries
        only (URI ``mode=ro``): no schema writes, no WAL switch, no upserts.
        This is how the control plane reads the data plane's evidence without
        ever becoming a second writer of its chain or mirror."""
        self._path = Path(path)
        self._read_only = read_only
        is_memory = str(self._path) == ":memory:"
        if read_only:
            # Fails if the file does not exist — callers treat that as "no
            # evidence yet" and retry on the next query. Autocommit
            # (isolation_level=None): a polling reader must never pin a read
            # snapshot in an implicit transaction, or it would keep serving
            # the past while the writer's chain grows.
            self._conn = sqlite3.connect(
                f"file:{self._path.as_posix()}?mode=ro", uri=True,
                check_same_thread=False, isolation_level=None)
            self._conn.row_factory = sqlite3.Row
            self._lock = threading.RLock()
            return
        if not is_memory:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        if not is_memory:
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def upsert_event(self, receipt: dict[str, Any]) -> None:
        params = {
            "seq": receipt["seq"],
            "ts": receipt["ts"],
            "actor": receipt["actor"],
            "action": receipt["action"],
            "target": receipt["target"],
            "verdict": receipt["verdict"],
            "block_reason": receipt.get("block_reason"),
            "prev_hash": receipt["prev_hash"],
            "record_hash": receipt["record_hash"],
            "receipt_json": json.dumps(receipt, separators=(",", ":")),
        }
        with self._lock:
            self._conn.execute(_INSERT_EVENT, params)
            self._conn.commit()

    def upsert_identity(self, ident: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(_INSERT_IDENTITY, ident)
            self._conn.commit()

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
        """Atomic check-and-increment of one quota row.

        A row whose ``window_start`` differs from the given one counts as zero
        (window rollover). If applying the deltas would exceed a given maximum,
        nothing is written and ``(False, current_count, current_bytes)`` is
        returned; otherwise the new totals are persisted and returned with True.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT window_start, count, bytes FROM quotas WHERE quota_key=?",
                (quota_key,),
            ).fetchone()
            in_window = row is not None and row["window_start"] == window_start
            cur_count = row["count"] if in_window else 0
            cur_bytes = row["bytes"] if in_window else 0
            new_count, new_bytes = cur_count + count_delta, cur_bytes + bytes_delta
            if (max_count is not None and new_count > max_count) or (
                max_bytes is not None and new_bytes > max_bytes
            ):
                return False, cur_count, cur_bytes
            self._conn.execute(
                "INSERT INTO quotas (quota_key, window_start, count, bytes) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(quota_key) DO UPDATE SET "
                "window_start=excluded.window_start, count=excluded.count, "
                "bytes=excluded.bytes",
                (quota_key, window_start, new_count, new_bytes),
            )
            self._conn.commit()
            return True, new_count, new_bytes

    def quota_usage(self, quota_key: str, window_start: str) -> tuple[int, int]:
        """(count, bytes) for the given window; zeros if absent or rolled over."""
        with self._lock:
            row = self._conn.execute(
                "SELECT window_start, count, bytes FROM quotas WHERE quota_key=?",
                (quota_key,),
            ).fetchone()
        if row is None or row["window_start"] != window_start:
            return 0, 0
        return row["count"], row["bytes"]

    def latest_seq(self) -> int | None:
        with self._lock:
            row = self._conn.execute("SELECT MAX(seq) AS m FROM events").fetchone()
        return row["m"] if row and row["m"] is not None else None

    def last_config_hash(self) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT receipt_json FROM events WHERE action='config_change' "
                "ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        if not row:
            return None
        return json.loads(row["receipt_json"]).get("policy_hash")

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT receipt_json FROM events ORDER BY seq DESC LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(r["receipt_json"]) for r in rows]

    # -- read-only aggregates (dashboard query surface; mirror only) ----------

    def _group_count(self, column: str, extra: str = "",
                     org: str | None = None) -> dict[str, int]:
        # ``column``/``extra`` are fixed identifiers from the callers below,
        # never user input — safe to interpolate; values are always bound.
        clauses, params = _org_filter(org)
        if extra:
            clauses.append(extra)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {column} AS k, COUNT(*) AS c FROM events {where} "
                f"GROUP BY {column} ORDER BY c DESC", params
            ).fetchall()
        return {r["k"]: r["c"] for r in rows}

    def verdict_counts(self, org: str | None = None) -> dict[str, int]:
        return self._group_count("verdict", org=org)

    def action_counts(self, org: str | None = None) -> dict[str, int]:
        return self._group_count("action", org=org)

    def block_reason_counts(self, org: str | None = None) -> dict[str, int]:
        return self._group_count("block_reason", "block_reason IS NOT NULL", org=org)

    def actor_counts(self, org: str | None = None) -> dict[str, int]:
        return self._group_count("actor", org=org)

    def org_counts(self, org: str | None = None) -> dict[str, int]:
        """Event counts per org, derived from the actor (Phase-6 tenancy view).

        ``spiffe://<org>/...`` -> org; ``user:...`` / mediator -> "system".
        Scoped to ``org`` when given, so a tenant's own view lists only itself
        — the org list is itself tenant-sensitive (it names your competitors)."""
        out: dict[str, int] = {}
        for actor, n in self.actor_counts(org).items():
            out[org_of(actor)] = out.get(org_of(actor), 0) + n
        return out

    def count_events(self, org: str | None = None) -> int:
        clauses, params = _org_filter(org)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            row = self._conn.execute(
                f"SELECT COUNT(*) AS c FROM events {where}", params).fetchone()
        return int(row["c"])

    def recent_filtered(
        self,
        *,
        limit: int = 50,
        actor: str | None = None,
        action: str | None = None,
        verdict: str | None = None,
        org: str | None = None,
    ) -> list[dict[str, Any]]:
        """Recent receipts, newest first, with optional exact-match filters."""
        clauses, params = _org_filter(org)
        for col, val in (("actor", actor), ("action", action), ("verdict", verdict)):
            if val is not None:
                clauses.append(f"{col}=?")
                params.append(val)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(max(1, min(limit, 500)))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT receipt_json FROM events {where} ORDER BY seq DESC LIMIT ?",
                params,
            ).fetchall()
        return [json.loads(r["receipt_json"]) for r in rows]

    def stats(self, org: str | None = None) -> dict[str, Any]:
        """One-shot summary for the dashboard/CLI (no chain verification)."""
        return {
            "events": self.count_events(org),
            "latest_seq": self.latest_seq(),
            "verdicts": self.verdict_counts(org),
            "actions": self.action_counts(org),
            "block_reasons": self.block_reason_counts(org),
            "actors": self.actor_counts(org),
            "orgs": self.org_counts(org),
        }

    def receipt_by_seq(self, seq: int, org: str | None = None) -> dict[str, Any] | None:
        """One receipt. Scoped: another tenant's seq is *not found*, never
        readable — a direct-seq fetch must not be an isolation bypass."""
        clauses, params = _org_filter(org)
        clauses.append("seq=?")
        params.append(seq)
        with self._lock:
            row = self._conn.execute(
                "SELECT receipt_json FROM events WHERE " + " AND ".join(clauses),
                params,
            ).fetchone()
        return json.loads(row["receipt_json"]) if row else None

    def search(
        self,
        *,
        query: str | None = None,
        since: str | None = None,
        until: str | None = None,
        actor: str | None = None,
        action: str | None = None,
        verdict: str | None = None,
        org: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Filtered + text-searched receipts, newest first.

        ``query`` is a case-insensitive substring over actor/target/block_reason;
        ``since``/``until`` bound the ``ts`` (ISO strings, lexicographically
        comparable); ``org`` scopes to one tenant (Phase-6 isolation). All
        filters are exact-match and bound as parameters."""
        clauses, params = _org_filter(org)
        for col, val in (("actor", actor), ("action", action), ("verdict", verdict)):
            if val is not None:
                clauses.append(f"{col}=?")
                params.append(val)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since)
        if until is not None:
            clauses.append("ts <= ?")
            params.append(until)
        if query:
            clauses.append("(actor LIKE ? OR target LIKE ? OR IFNULL(block_reason,'') LIKE ?)")
            like = f"%{query}%"
            params.extend([like, like, like])
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(max(1, min(limit, 500)))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT receipt_json FROM events {where} ORDER BY seq DESC LIMIT ?",
                params,
            ).fetchall()
        return [json.loads(r["receipt_json"]) for r in rows]

    def iter_receipts(
        self,
        *,
        since: str | None = None,
        until: str | None = None,
        org: str | None = None,
        batch: int = 1000,
    ) -> Iterator[dict[str, Any]]:
        """Every receipt in the window, newest first — uncapped.

        ``search`` is capped for interactive endpoints; anything that must
        *count* the ledger (a signed attestation) pages through here instead,
        keyset-paginated on ``seq`` so memory stays bounded."""
        base, base_params = _org_filter(org)
        if since is not None:
            base.append("ts >= ?")
            base_params.append(since)
        if until is not None:
            base.append("ts <= ?")
            base_params.append(until)
        last_seq: int | None = None
        while True:
            clauses, params = list(base), list(base_params)
            if last_seq is not None:
                clauses.append("seq < ?")
                params.append(last_seq)
            where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
            params.append(max(1, batch))
            with self._lock:
                rows = self._conn.execute(
                    f"SELECT seq, receipt_json FROM events {where} "
                    "ORDER BY seq DESC LIMIT ?", params,
                ).fetchall()
            if not rows:
                return
            for r in rows:
                yield json.loads(r["receipt_json"])
            last_seq = rows[-1]["seq"]

    def time_series(self, *, buckets: int = 24, span_hours: int = 24,
                    now: str | None = None, org: str | None = None) -> list[dict[str, Any]]:
        """Counts per time bucket (verdict breakdown) over the trailing window.

        ``ts`` is an ISO-8601 string; SQLite ``strftime`` parses it. Buckets are
        even divisions of ``span_hours`` ending at ``now`` (or the latest event).
        Returns oldest-first list of {bucket_start, total, allow, block, strip,
        warn}."""
        org_clauses, org_params = _org_filter(org)
        with self._lock:
            if now is None:
                # The window ends at the tenant's own latest event — an empty
                # org must not inherit another tenant's clock.
                where = ("WHERE " + " AND ".join(org_clauses)) if org_clauses else ""
                row = self._conn.execute(
                    f"SELECT MAX(ts) AS m FROM events {where}", org_params).fetchone()
                now = row["m"] if row and row["m"] else None
            if now is None:
                return []
            clauses = [*org_clauses,
                       "ts >= strftime('%Y-%m-%dT%H:%M:%fZ', ?, ?)", "ts <= ?"]
            rows = self._conn.execute(
                "SELECT ts, verdict FROM events WHERE " + " AND ".join(clauses),
                [*org_params, now, f"-{span_hours} hours", now],
            ).fetchall()
        # Bucket in Python (portable; avoids SQLite epoch-math edge cases).
        from datetime import datetime, timedelta

        def parse(s: str) -> datetime:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))

        end = parse(now)
        start = end - timedelta(hours=span_hours)
        width = (end - start) / buckets
        series = [{"bucket_start": (start + width * i).isoformat().replace("+00:00", "Z"),
                   "total": 0, "allow": 0, "block": 0, "strip": 0, "warn": 0, "ask": 0}
                  for i in range(buckets)]
        for r in rows:
            try:
                idx = int((parse(r["ts"]) - start) / width)
            except (ValueError, ZeroDivisionError):
                continue
            idx = max(0, min(buckets - 1, idx))
            series[idx]["total"] += 1
            v = r["verdict"]
            if v in series[idx]:
                series[idx][v] += 1
        return series

    def reconcile(self, receipts: Iterable[dict[str, Any]]) -> int:
        n = 0
        for r in receipts:
            self.upsert_event(r)
            n += 1
        return n

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "SqliteMirror":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
