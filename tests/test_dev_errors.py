"""The development_errors recorder — writes failure rows, never breaks tests."""

from __future__ import annotations

import sqlite3

from dev_errors import DevErrorRecorder, make_run_id


def _row_count(db_path) -> int:
    conn = sqlite3.connect(str(db_path))
    try:
        return conn.execute("SELECT COUNT(*) FROM development_errors").fetchone()[0]
    finally:
        conn.close()


def test_records_a_failure_row(tmp_path):
    db = tmp_path / "dev.sqlite"
    rec = DevErrorRecorder(make_run_id(), db_path=db)
    rec.record(
        nodeid="tests/test_x.py::test_y", test_file="tests/test_x.py", phase="call",
        outcome="failed", exc_type="AssertionError", message="assert 1 == 2",
        longrepr="…traceback…", duration=0.01,
    )
    rec.close()
    conn = sqlite3.connect(str(db)); conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM development_errors").fetchone()
    conn.close()
    assert row["nodeid"] == "tests/test_x.py::test_y"
    assert row["outcome"] == "failed" and row["exc_type"] == "AssertionError"
    assert row["run_id"] == rec.run_id and row["ts"]


def test_multiple_rows_grouped_by_run(tmp_path):
    db = tmp_path / "dev.sqlite"
    rec = DevErrorRecorder("run-42", db_path=db)
    for i in range(3):
        rec.record(nodeid=f"t::{i}", test_file="t", phase="call", outcome="error",
                   exc_type="ValueError", message=f"boom {i}", longrepr=None, duration=None)
    rec.close()
    assert _row_count(db) == 3


def test_long_fields_truncated(tmp_path):
    db = tmp_path / "dev.sqlite"
    rec = DevErrorRecorder("run", db_path=db)
    rec.record(nodeid="t", test_file="t", phase="call", outcome="failed",
               exc_type="E", message="x" * 5000, longrepr="y" * 20000, duration=1.0)
    rec.close()
    conn = sqlite3.connect(str(db))
    msg, longrepr = conn.execute("SELECT message, longrepr FROM development_errors").fetchone()
    conn.close()
    assert len(msg) == 2000 and len(longrepr) == 8000


def test_recording_never_raises_on_bad_path(tmp_path):
    # a directory where a file is expected -> connect fails -> record is a no-op
    bad = tmp_path / "as_dir"
    bad.mkdir()
    rec = DevErrorRecorder("run", db_path=bad)
    rec.record(nodeid="t", test_file="t", phase="call", outcome="failed",
               exc_type="E", message="m", longrepr=None, duration=None)
    rec.close()  # must not raise
    assert rec.recorded == 0
