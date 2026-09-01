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

Only PENDING state persists. Resolutions delete the row (receipts are the
record of what was decided), so an unconsumed approval dies with the process
instead of becoming a replayable allow-token, and lapsed rows are pruned on
the next load — the table holds live state, never history.

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
        """A resolution removes the row: the store holds live pending state
        only — receipts are the record of what was decided. This also means an
        approved request_id can never be replayed across a restart."""
        del status, resolved_by  # recorded in the resolution receipt, not here
        with self._lock, self._conn:
            self._conn.execute(
                "DELETE FROM approvals WHERE request_id = ?", (request_id,))

    def load_approvals(self) -> list[dict]:
        """The pending approvals, each with ``age_s`` — seconds elapsed since
        the original wall-clock submission, so a rehydrating gate can re-anchor
        the request in its own monotonic clock without moving the deadline.

        Wall time can step backward between submission and this read (NTP
        correction, VM snapshot restore); a row whose age comes out negative is
        from "the future" and is dropped as lapsed — fail closed, never a fresh
        deadline. Rows already past their deadline are pruned here too, so the
        table never accumulates history.
        """
        now = time.time()
        rows_out: list[dict] = []
        with self._lock, self._conn:
            rows = self._conn.execute(
                "SELECT request_id, actor, tool, created_at_wall, timeout_s "
                "FROM approvals"
            ).fetchall()
            for request_id, actor, tool, created_at_wall, timeout_s in rows:
                age_s = now - created_at_wall
                if age_s < 0 or age_s >= timeout_s:
                    self._conn.execute(
                        "DELETE FROM approvals WHERE request_id = ?", (request_id,))
                    continue
                rows_out.append({
                    "request_id": request_id, "actor": actor, "tool": tool,
                    "age_s": age_s, "timeout_s": timeout_s,
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
