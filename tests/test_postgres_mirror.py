"""Phase 6 — the Postgres mirror: the concurrent-writer path.

Why this exists: SQLite serializes writers behind one *process-local* lock. Two
mediators sharing a mirror would race the ``quotas`` table, and a raced budget
check is a denial-of-wallet hole — both writers read "99 of 100 used", both
allow, and the tenant spends 101. Postgres gives us a cross-process lock.

These tests need a live Postgres. Point ``AL_TEST_POSTGRES_DSN`` at one, e.g.

    docker run -d --name al-pg-test -e POSTGRES_PASSWORD=al -e POSTGRES_DB=al \
        -p 15432:5432 postgres:16-alpine
    AL_TEST_POSTGRES_DSN=postgresql://postgres:al@127.0.0.1:15432/al uv run pytest

They auto-skip when it is absent, so the suite stays green on a bare laptop.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from al_core.config import load_settings

DSN = os.environ.get("AL_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(
    not DSN, reason="no AL_TEST_POSTGRES_DSN — Postgres mirror tests need a live server")


@pytest.fixture
def mirror():
    from al_core.audit.pg import PostgresMirror

    m = PostgresMirror(DSN)
    with m._conn.cursor() as cur:            # noqa: SLF001 — test-only reset
        cur.execute("TRUNCATE events; TRUNCATE quotas;")
    yield m
    m.close()


def _receipt(seq: int, actor: str, verdict: str = "allow", **kw) -> dict:
    return {
        "v": 1, "seq": seq, "ts": f"2026-07-12T00:00:{seq % 60:02d}.000Z",
        "actor": actor, "action": kw.get("action", "fetch"),
        "target": kw.get("target", "https://example.com"), "verdict": verdict,
        "block_reason": kw.get("block_reason"),
        "prev_hash": "sha256:" + "0" * 64, "record_hash": f"sha256:{seq:064d}",
        "sig": "ed25519:x",
    }


# -- THE test: concurrent writers cannot overspend a budget -------------------------

def test_concurrent_writers_never_exceed_a_budget(mirror):
    """16 threads race one org's budget of 100. Exactly 100 must be admitted.

    On a process-local lock this is the classic double-spend; the row lock makes
    the check-and-increment atomic across writers."""
    from al_core.audit.pg import PostgresMirror

    budget, attempts, writers = 100, 200, 16

    def worker(_: int) -> int:
        # A *separate connection* per worker — i.e. a separate writer, which is
        # the whole point (one shared connection would prove nothing).
        m = PostgresMirror(DSN)
        allowed = 0
        try:
            for _ in range(attempts // writers):
                ok, _, _ = m.quota_try_consume(
                    "org:acme", "2026-07-12", count_delta=1, max_count=budget)
                allowed += 1 if ok else 0
        finally:
            m.close()
        return allowed

    with ThreadPoolExecutor(max_workers=writers) as pool:
        admitted = sum(pool.map(worker, range(writers)))

    assert admitted == budget, f"admitted {admitted}, budget {budget} — double-spend"
    count, _ = mirror.quota_usage("org:acme", "2026-07-12")
    assert count == budget


def test_concurrent_token_budget_is_atomic(mirror):
    from al_core.audit.pg import PostgresMirror

    def worker(_: int) -> int:
        m = PostgresMirror(DSN)
        try:
            ok, _, _ = m.quota_try_consume(
                "org:globex", "2026-07-12", bytes_delta=100, max_bytes=500)
            return 1 if ok else 0
        finally:
            m.close()

    with ThreadPoolExecutor(max_workers=10) as pool:
        admitted = sum(pool.map(worker, range(10)))
    assert admitted == 5  # 5 x 100 tokens fits in 500, the rest are denied
    _, tokens = mirror.quota_usage("org:globex", "2026-07-12")
    assert tokens == 500


def test_window_rollover_resets(mirror):
    ok, count, _ = mirror.quota_try_consume("k", "2026-07-12", count_delta=1, max_count=1)
    assert ok and count == 1
    assert not mirror.quota_try_consume("k", "2026-07-12", count_delta=1, max_count=1)[0]
    # a new UTC day is a fresh window
    ok, count, _ = mirror.quota_try_consume("k", "2026-07-13", count_delta=1, max_count=1)
    assert ok and count == 1


# -- parity with the SQLite mirror (the config swap must be a no-op) ------------------

def test_concurrent_event_writers_do_not_lose_receipts(mirror):
    from al_core.audit.pg import PostgresMirror

    def writer(base: int) -> None:
        m = PostgresMirror(DSN)
        try:
            for i in range(25):
                m.upsert_event(_receipt(base * 25 + i, "spiffe://acme/agent/bot"))
        finally:
            m.close()

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(writer, range(8)))
    assert mirror.count_events() == 200


def test_org_scoping_matches_sqlite(mirror):
    for i in range(3):
        mirror.upsert_event(_receipt(i, "spiffe://acme/agent/bot"))
    mirror.upsert_event(_receipt(3, "spiffe://globex/agent/bot", "block",
                                 block_reason="TOOL_DENIED"))
    mirror.upsert_event(_receipt(4, "user:console"))

    assert mirror.count_events("acme") == 3
    assert mirror.count_events("globex") == 1
    assert mirror.count_events("system") == 1
    assert mirror.count_events() == 5

    acme = mirror.recent_filtered(org="acme")
    assert {r["actor"] for r in acme} == {"spiffe://acme/agent/bot"}
    # a cross-tenant seq is NOT FOUND, exactly as in SQLite
    assert mirror.receipt_by_seq(3, "acme") is None
    assert mirror.receipt_by_seq(3, "globex")["actor"] == "spiffe://globex/agent/bot"
    assert mirror.org_counts() == {"acme": 3, "globex": 1, "system": 1}
    assert mirror.block_reason_counts("globex") == {"TOOL_DENIED": 1}
    assert mirror.search(query="globex", org="acme") == []


def test_stats_and_trends_scope(mirror):
    for i in range(4):
        mirror.upsert_event(_receipt(i, "spiffe://acme/agent/bot"))
    mirror.upsert_event(_receipt(9, "spiffe://globex/agent/bot"))
    stats = mirror.stats("acme")
    assert stats["events"] == 4 and stats["orgs"] == {"acme": 4}
    series = mirror.time_series(org="acme", span_hours=24)
    assert sum(b["total"] for b in series) == 4


# -- config swap ---------------------------------------------------------------------

def test_config_selects_postgres_backend():
    s = load_settings(None, admin_api_token="t",
                      audit={"backend": "postgres", "dsn": DSN})
    assert s.audit.backend == "postgres"
    assert s.audit.dsn.get_secret_value() == DSN  # SecretStr — never printed


def test_postgres_backend_without_dsn_is_rejected():
    with pytest.raises(Exception, match="audit.dsn"):
        load_settings(None, admin_api_token="t", audit={"backend": "postgres"})


def test_runtime_boots_on_postgres_and_chain_verifies(tmp_path):
    """The swap is a config change, nothing else: same JSONL, same chain, same
    receipts — only the mirror moves."""
    from al_core.audit.pg import PostgresMirror
    from al_core.runtime import Runtime

    m = PostgresMirror(DSN)
    with m._conn.cursor() as cur:  # noqa: SLF001
        cur.execute("TRUNCATE events; TRUNCATE quotas;")
    m.close()

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(f"mode: balanced\naudit:\n  backend: postgres\n  dsn: {DSN}\n",
                   encoding="utf-8")
    rt = Runtime(cfg, data_dir=tmp_path / "data")
    rt.record(actor="spiffe://acme/agent/bot", action="fetch",
              target="https://example.com", verdict="allow")
    rt.record(actor="spiffe://globex/agent/bot", action="mcp_tool_call",
              target="tool:exec_shell", verdict="block", block_reason="TOOL_DENIED")

    # evidence is unchanged: the JSONL chain still verifies from genesis
    assert rt.ledger.verify(rt.public_key) >= 2
    # and the mirror answers org-scoped queries
    assert rt.ledger.db.count_events("acme") == 1
    assert rt.ledger.db.receipt_by_seq(
        rt.ledger.db.latest_seq(), "acme") is None  # that one is globex's
    rt.close()
