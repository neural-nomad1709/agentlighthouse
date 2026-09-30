"""SQLite persistence for the L4 gates' live state: pending HITL approvals and
taint marks, rehydrated on boot. Pending approvals survive a restart so an
in-flight production approval is not silently dropped; taint survives because
it is monotonic within a session — a restart must not launder it.

Deadlines are the subtle part: the gates measure time with a **monotonic**
clock, whose epoch resets every process. The store therefore keeps the wall
time of submission, and rehydration re-expresses it in the new process's
monotonic clock preserving the *elapsed age*, so a normally-running clock can
never extend a deadline. Wall time itself can step backward (NTP correction,
VM snapshot restore); a row whose age computes negative is treated as lapsed —
fail closed. A backward step smaller than the elapsed age undercounts it by at
most the step; the deadline is still bounded by the original timeout.

The store is also the crossing point between planes: the data plane files a
request, the control plane (another process, pointed at the same file via
``control.dataplane_dir``) resolves it, and the data plane executes the call.
A resolution therefore updates the row rather than deleting it. An approval is
a **grant**: bound to the actor, tool, argument digest and session that filed
it, valid for ``timeout_s`` after it was given, and consumed exactly once by an
atomic delete — two consumers racing on one file cannot both win. A denial
stays readable for the same window so the filing plane can report it. Lapsed
requests, spent grants and aged-out denials are pruned — the table holds live
state, never history; receipts remain the record of what was decided.

Like the mirror, the single connection is opened ``check_same_thread=False``
and guarded by a lock; writes are one-per-decision, so contention is nil.
This is state, not evidence — receipts remain the audit trail.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS approval_requests (
    request_id       TEXT PRIMARY KEY,
    actor            TEXT NOT NULL,
    tool             TEXT NOT NULL,
    created_at_wall  REAL NOT NULL,
    timeout_s        REAL NOT NULL,
    status           TEXT NOT NULL,
    resolved_by      TEXT,
    resolved_at_wall REAL,
    detail           TEXT,
    session          TEXT,
    args_digest      TEXT
);
CREATE TABLE IF NOT EXISTS taint (
    session_id TEXT NOT NULL,
    source     TEXT NOT NULL,
    marked_at  REAL NOT NULL,
    PRIMARY KEY (session_id, source)
);
"""


class CapabilityStore:
    """Persistent state for the L4 gates. One file, two tables."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.Lock()
        with self._lock, self._conn:
            self._conn.executescript(_SCHEMA)

    # -- approvals ---------------------------------------------------------

    def save_approval(
        self, request_id: str, actor: str, tool: str, timeout_s: float,
        *, created_at_wall: float | None = None,
        detail: str | None = None, session: str | None = None,
        args_digest: str | None = None,
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO approval_requests "
                "(request_id, actor, tool, created_at_wall, timeout_s, status, "
                " resolved_by, resolved_at_wall, detail, session, args_digest) "
                "VALUES (?, ?, ?, ?, ?, 'pending', NULL, NULL, ?, ?, ?)",
                (request_id, actor, tool, created_at_wall or time.time(), timeout_s,
                 detail, session, args_digest),
            )

    def resolve_approval(self, request_id: str, status: str, resolved_by: str | None) -> bool:
        """Resolve a still-pending, unlapsed request. False when another
        process resolved it first or its deadline passed — the caller lost."""
        now = time.time()
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE approval_requests SET status = ?, resolved_by = ?, "
                "resolved_at_wall = ? WHERE request_id = ? AND status = 'pending' "
                "AND created_at_wall <= ? AND ? - created_at_wall < timeout_s",
                (status, resolved_by, now, request_id, now, now),
            )
            return cur.rowcount == 1

    def consume_approval(self, request_id: str) -> bool:
        """Spend an approval grant. The delete is the atomic claim: exactly one
        caller, in any process, gets True for a given grant."""
        now = time.time()
        with self._lock, self._conn:
            cur = self._conn.execute(
                "DELETE FROM approval_requests WHERE request_id = ? "
                "AND status = 'approved' AND resolved_at_wall <= ? "
                "AND ? - resolved_at_wall < timeout_s",
                (request_id, now, now),
            )
            return cur.rowcount == 1

    def approval(self, request_id: str) -> dict | None:
        """One live row (see :meth:`approval_rows`), or None."""
        rows = self._live_rows("WHERE request_id = ?", (request_id,))
        return rows[0] if rows else None

    def load_approvals(self) -> list[dict]:
        """The pending approvals, each with ``age_s`` — seconds elapsed since
        the original wall-clock submission, so a rehydrating gate can re-anchor
        the request in its own monotonic clock without moving the deadline.

        Wall time can step backward between submission and this read (NTP
        correction, VM snapshot restore); a row whose age comes out negative is
        from "the future" and is dropped as lapsed — fail closed, never a fresh
        deadline. Rows past their window are pruned here too, so the table
        never accumulates history.
        """
        return [r for r in self._live_rows("", ()) if r["status"] == "pending"]

    def live_approvals(self) -> list[dict]:
        """Every row still inside its window: pending requests, unspent
        grants and recent denials (see :meth:`_live_rows`)."""
        return self._live_rows("", ())

    def _live_rows(self, where: str, params: tuple) -> list[dict]:
        """Rows still inside their window, each with ``age_s`` and (once
        resolved) ``resolved_age_s``. Expired rows are deleted on the way."""
        now = time.time()
        rows_out: list[dict] = []
        with self._lock, self._conn:
            rows = self._conn.execute(
                "SELECT request_id, actor, tool, created_at_wall, timeout_s, status, "
                "resolved_by, resolved_at_wall, detail, session, args_digest "
                f"FROM approval_requests {where}", params,
            ).fetchall()
            for (request_id, actor, tool, created_at_wall, timeout_s, status,
                 resolved_by, resolved_at_wall, detail, session, args_digest) in rows:
                age_s = now - created_at_wall
                if status == "pending":
                    expired = age_s < 0 or age_s >= timeout_s
                    resolved_age_s = None
                else:
                    resolved_age_s = now - (resolved_at_wall or 0.0)
                    expired = resolved_age_s < 0 or resolved_age_s >= timeout_s
                if expired:
                    self._conn.execute(
                        "DELETE FROM approval_requests WHERE request_id = ?", (request_id,))
                    continue
                rows_out.append({
                    "request_id": request_id, "actor": actor, "tool": tool,
                    "age_s": age_s, "timeout_s": timeout_s, "status": status,
                    "resolved_by": resolved_by, "resolved_age_s": resolved_age_s,
                    "detail": detail, "session": session, "args_digest": args_digest,
                })
        return rows_out

    # -- taint ---------------------------------------------------------------

    def mark_taint(self, session_id: str, source: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO taint (session_id, source, marked_at) VALUES (?, ?, ?)",
                (session_id, source, time.time()),
            )

    def clear_taint(self, session_id: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM taint WHERE session_id = ?", (session_id,))

    def load_taint(self) -> dict[str, list[str]]:
        """session_id -> sources, in the order they were marked."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT session_id, source FROM taint ORDER BY marked_at, rowid"
            ).fetchall()
        sessions: dict[str, list[str]] = {}
        for session_id, source in rows:
            sessions.setdefault(session_id, []).append(source)
        return sessions

    def close(self) -> None:
        with self._lock:
            self._conn.close()


__all__ = ["CapabilityStore"]
