"""Persist test failures/errors to a dedicated SQLite table: development_errors.

Kept in its OWN database file (``data/development.sqlite``), never the evidence
mirror (``al.sqlite``) — test diagnostics must not mingle with security
receipts. One row per failing/erroring test phase, per run. Purely a dev-time
observability aid; the file is gitignored (under ``data/``).

Wired from ``conftest.py`` via ``pytest_runtest_logreport`` + a session-end
summary. Recording never raises into the test run — a broken recorder must not
turn a green suite red.
"""

from __future__ import annotations

import datetime as _dt
import os
import sqlite3
import subprocess
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "data" / "development.sqlite"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS development_errors (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,   -- ISO-8601 UTC when recorded
    run_id      TEXT    NOT NULL,   -- groups all rows from one pytest run
    git_commit  TEXT,               -- short HEAD sha at record time
    nodeid      TEXT    NOT NULL,   -- e.g. tests/test_x.py::test_y[case]
    test_file   TEXT    NOT NULL,   -- source file of the test
    phase       TEXT    NOT NULL,   -- setup | call | teardown
    outcome     TEXT    NOT NULL,   -- failed | error
    exc_type    TEXT,               -- exception class name
    message     TEXT,               -- short exception message (one line)
    longrepr    TEXT,               -- truncated traceback / failure repr
    duration    REAL                -- phase duration in seconds
);
CREATE INDEX IF NOT EXISTS idx_dev_errors_run    ON development_errors(run_id);
CREATE INDEX IF NOT EXISTS idx_dev_errors_nodeid ON development_errors(nodeid);
"""


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds")


def _git_commit() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        return out.stdout.strip() or None
    except Exception:
        return None


class DevErrorRecorder:
    """Opens the dev-errors db lazily and appends failure rows for one run."""

    def __init__(self, run_id: str, db_path: Path = DB_PATH) -> None:
        self.run_id = run_id
        self._db_path = db_path
        self._commit = _git_commit()
        self._conn: sqlite3.Connection | None = None
        self.recorded = 0

    def _connect(self) -> sqlite3.Connection | None:
        if self._conn is None:
            try:
                self._db_path.parent.mkdir(parents=True, exist_ok=True)
                self._conn = sqlite3.connect(str(self._db_path))
                self._conn.executescript(_SCHEMA)
                self._conn.commit()
            except Exception:
                self._conn = None  # recording is best-effort; never break tests
        return self._conn

    def record(
        self,
        *,
        nodeid: str,
        test_file: str,
        phase: str,
        outcome: str,
        exc_type: str | None,
        message: str | None,
        longrepr: str | None,
        duration: float | None,
    ) -> None:
        conn = self._connect()
        if conn is None:
            return
        try:
            conn.execute(
                "INSERT INTO development_errors "
                "(ts, run_id, git_commit, nodeid, test_file, phase, outcome, "
                " exc_type, message, longrepr, duration) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    _utc_now(), self.run_id, self._commit, nodeid, test_file, phase,
                    outcome, exc_type,
                    (message or "")[:2000],
                    (longrepr or "")[:8000],
                    duration,
                ),
            )
            conn.commit()
            self.recorded += 1
        except Exception:
            pass  # best-effort

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None


def make_run_id() -> str:
    """Sortable, collision-resistant run id (UTC ts + pid)."""
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"{stamp}-{os.getpid()}"


__all__ = ["DB_PATH", "DevErrorRecorder", "make_run_id"]
