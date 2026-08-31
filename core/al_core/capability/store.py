"""SQLite persistence for HITL approvals and taint marks (AL-0.2).

`HitlGate` and `TaintTracker` held their state in process memory, so a mediator
restart dropped pending approvals (fail-closed, but every in-flight production
approval silently died) and cleared taint — a fail-open, since taint is
documented as monotonic within a session. This store sits next to the ledger
mirror and rehydrates both on boot.

Deadlines are the subtle part: the gates measure time with a **monotonic**
clock, whose epoch resets every process. The store therefore keeps the wall
time of submission, and rehydration re-expresses it in the new process's
monotonic clock preserving the *elapsed age* — so persistence can never extend
a deadline (the acceptance the brief demands).

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
CREATE TABLE IF NOT EXISTS approvals (
    request_id      TEXT PRIMARY KEY,
    actor           TEXT NOT NULL,
    tool            TEXT NOT NULL,
    created_at_wall REAL NOT NULL,
    timeout_s       REAL NOT NULL,
    status          TEXT NOT NULL,
    resolved_by     TEXT
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
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO approvals "
                "(request_id, actor, tool, created_at_wall, timeout_s, status, resolved_by) "
                "VALUES (?, ?, ?, ?, ?, 'pending', NULL)",
                (request_id, actor, tool, created_at_wall or time.time(), timeout_s),
            )

    def resolve_approval(self, request_id: str, status: str, resolved_by: str | None) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE approvals SET status = ?, resolved_by = ? WHERE request_id = ?",
                (status, resolved_by, request_id),
            )

    def load_approvals(self) -> list[dict]:
        """All stored approvals, each with ``age_s`` — seconds elapsed since the
        original wall-clock submission, so a rehydrating gate can re-anchor the
        request in its own monotonic clock without moving the deadline."""
        now = time.time()
        with self._lock:
            rows = self._conn.execute(
                "SELECT request_id, actor, tool, created_at_wall, timeout_s, "
                "status, resolved_by FROM approvals"
            ).fetchall()
        return [{
            "request_id": r[0], "actor": r[1], "tool": r[2],
            "age_s": max(0.0, now - r[3]), "timeout_s": r[4],
            "status": r[5], "resolved_by": r[6],
        } for r in rows]

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
