"""Evidence dashboard — read-only API auth, aggregates, static serving.

The dashboard exposes evidence and nothing else; these tests prove it is
admin-token gated (fail-closed on missing/wrong token), that the aggregates
reflect the ledger, and that the static page serves.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from al_core.app import create_app
from al_core.runtime import Runtime

TOKEN = "dashboard-admin-token"


def _runtime(tmp_path, yaml_text="mode: balanced\n") -> Runtime:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(yaml_text, encoding="utf-8")
    return Runtime(cfg, data_dir=tmp_path / "data", admin_api_token=TOKEN)


def _seed_events(rt: Runtime) -> None:
    """Record a spread of receipts so aggregates are non-trivial."""
    rt.record(actor="user:alice", action="llm_call", target="openai:gpt-4o", verdict="allow")
    rt.record(actor="user:alice", action="fetch", target="https://x/y", verdict="block",
              block_reason="INJECTION_BLOCKED",
              findings=[{"scanner": "injection", "rule_id": "override.x", "severity": "high",
                         "owasp": "ASI01"}])
    rt.record(actor="user:bob", action="fetch", target="https://x/z", verdict="strip",
              redaction={"aws-access-key": 1})
    # a real agent identity so org-scoping (Phase-6 tenancy) is exercised
    rt.record(actor="spiffe://acme/agent/claude-code", action="mcp_tool_call",
              target="tool:exec_shell", verdict="block", block_reason="TOOL_DENIED",
              findings=[{"scanner": "tool_policy", "rule_id": "policy.explicit_deny",
                         "severity": "high", "owasp": "ASI02"}])


# -- DB aggregate queries --------------------------------------------------------

def test_sqlite_aggregates(tmp_path):
    rt = _runtime(tmp_path)
    _seed_events(rt)
    db = rt.ledger.db
    v = db.verdict_counts()
    assert v["allow"] >= 2 and v["block"] == 2 and v["strip"] == 1  # +1 config:boot allow
    assert db.action_counts()["fetch"] == 2
    assert db.block_reason_counts() == {"INJECTION_BLOCKED": 1, "TOOL_DENIED": 1}
    assert set(db.actor_counts()) >= {"user:alice", "user:bob", "spiffe://acme/agent/claude-code"}
    stats = db.stats()
    assert stats["events"] == db.count_events()
    rt.close()


def test_recent_filtered(tmp_path):
    rt = _runtime(tmp_path)
    _seed_events(rt)
    db = rt.ledger.db
    only_bob = db.recent_filtered(actor="user:bob")
    assert only_bob and all(r["actor"] == "user:bob" for r in only_bob)
    only_block = db.recent_filtered(verdict="block")
    assert only_block and all(r["verdict"] == "block" for r in only_block)
    assert db.recent_filtered(action="fetch", verdict="strip")[0]["actor"] == "user:bob"
    rt.close()


def test_recent_filtered_limit_capped(tmp_path):
    rt = _runtime(tmp_path)
    for i in range(20):
        rt.record(actor="user:a", action="fetch", target=f"t{i}", verdict="allow")
    assert len(rt.ledger.db.recent_filtered(limit=5)) == 5
    assert len(rt.ledger.db.recent_filtered(limit=9999)) <= 500
    rt.close()


# -- API auth --------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    # Seed the ledger, then release it so the app boots on the persisted data
    # (verify-on-startup reconciles the SQLite mirror from the JSONL).
    rt = _runtime(tmp_path)
    _seed_events(rt)
    rt.close()
    application = create_app(tmp_path / "cfg.yaml", data_dir=tmp_path / "data",
                             admin_api_token=TOKEN)
    with TestClient(application) as c:
        yield c


def _auth(headers=True):
    return {"Authorization": f"Bearer {TOKEN}"} if headers else {}


def test_summary_requires_token(client):
    assert client.get("/api/summary").status_code == 401
    assert client.get("/api/summary", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_summary_ok_with_token(client):
    r = client.get("/api/summary", headers=_auth())
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "balanced"
    assert body["chain"]["verified"] is True
    assert body["verdicts"]["block"] == 2 and body["verdicts"]["strip"] == 1
    assert "INJECTION_BLOCKED" in body["block_reasons"]


def test_receipts_requires_token(client):
    assert client.get("/api/receipts").status_code == 401


def test_receipts_filtered(client):
    r = client.get("/api/receipts", headers=_auth(), params={"verdict": "block"})
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 2  # the alice injection + acme tool-deny blocks
    reasons = {x["block_reason"] for x in data["receipts"]}
    assert reasons == {"INJECTION_BLOCKED", "TOOL_DENIED"}
    # findings surface, but never plaintext
    assert all(x["findings"] for x in data["receipts"])


def test_receipts_no_plaintext_secret_leak(client):
    # a redaction receipt exposes counts only
    r = client.get("/api/receipts", headers=_auth(), params={"verdict": "strip"})
    body = r.text
    assert "aws-access-key" in body  # the class name is fine
    assert "AKIA" not in body        # no secret material


def test_chain_endpoint(client):
    assert client.get("/api/chain").status_code == 401
    r = client.get("/api/chain", headers=_auth())
    assert r.status_code == 200 and r.json()["verified"] is True


def test_dashboard_route(client):
    # /dashboard serves the built Vite app when present, else a clear 404.
    from al_core.app import _DASHBOARD_DIST

    r = client.get("/dashboard")  # TestClient follows the redirect to /dashboard/
    if (_DASHBOARD_DIST / "index.html").exists():
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert "AgentLighthouse" in r.text  # built index.html title
        assert TOKEN not in r.text          # ships no secrets
    else:
        assert r.status_code == 404 and r.json()["error"] == "dashboard_not_built"


def test_healthz_open(client):
    # health stays unauthenticated (load balancers need it)
    assert client.get("/healthz").status_code == 200


# -- rich dashboard API (search / trends / detail / verify) --------------------

def test_search_requires_token(client):
    assert client.get("/api/search").status_code == 401


def test_search_by_query(client):
    r = client.get("/api/search", headers=_auth(), params={"q": "INJECTION"})
    assert r.status_code == 200
    receipts = r.json()["receipts"]
    assert receipts and all("INJECTION" in json.dumps(x) for x in receipts)


def test_search_by_actor_and_verdict(client):
    r = client.get("/api/search", headers=_auth(),
                   params={"actor": "user:bob", "verdict": "strip"})
    assert r.status_code == 200
    assert all(x["actor"] == "user:bob" and x["verdict"] == "strip"
               for x in r.json()["receipts"])


def test_trends_buckets(client):
    r = client.get("/api/trends", headers=_auth(), params={"buckets": 6, "span_hours": 24})
    assert r.status_code == 200
    series = r.json()["series"]
    assert len(series) == 6
    assert sum(b["total"] for b in series) >= 1
    assert all({"bucket_start", "total", "allow", "block"} <= set(b) for b in series)


def test_receipt_detail(client):
    r = client.get("/api/receipts/1", headers=_auth())
    assert r.status_code == 200 and r.json()["seq"] == 1


def test_receipt_detail_not_found(client):
    assert client.get("/api/receipts/9999", headers=_auth()).status_code == 404


def test_verify_endpoint_passes_for_genuine_receipt(client):
    r = client.get("/api/verify/1", headers=_auth())
    assert r.status_code == 200
    body = r.json()
    assert body["verified"] is True and body["error"] is None
    assert body["sig"].startswith("ed25519:")


def test_verify_requires_token(client):
    assert client.get("/api/verify/1").status_code == 401


def test_db_search_time_bounds(tmp_path):
    rt = _runtime(tmp_path)
    _seed_events(rt)
    # since far in the future -> nothing
    assert rt.ledger.db.search(since="2999-01-01T00:00:00.000Z") == []
    # wide-open -> everything
    assert len(rt.ledger.db.search()) == rt.ledger.db.count_events()
    rt.close()


def test_db_time_series_empty_when_no_events(tmp_path):
    from al_core.audit.db import SqliteMirror
    assert SqliteMirror(":memory:").time_series() == []


# -- RBAC session + org scoping (Phase-6 readiness) ----------------------------

def test_session_requires_token(client):
    assert client.get("/api/session").status_code == 401


def test_session_reports_role_and_caps(client):
    r = client.get("/api/session", headers=_auth())
    assert r.status_code == 200
    body = r.json()
    assert body["role"] == "admin"
    assert set(body["capabilities"]) >= {"view", "verify", "approve", "configure"}
    assert "acme" in body["orgs"] and "system" in body["orgs"]


def test_org_derivation():
    from al_core.audit.db import org_of
    assert org_of("spiffe://acme/agent/claude-code") == "acme"
    assert org_of("user:alice") == "system"
    assert org_of("spiffe://local/al-core") == "local"


def test_summary_includes_orgs(client):
    body = client.get("/api/summary", headers=_auth()).json()
    assert body["orgs"]["acme"] >= 1  # the seeded block receipt is acme
    assert "system" in body["orgs"]   # user:* + mediator


def test_search_org_scopes_tenant(client):
    acme = client.get("/api/search", headers=_auth(), params={"org": "acme"}).json()
    assert acme["receipts"] and all(r["actor"].startswith("spiffe://acme/")
                                    for r in acme["receipts"])
    system = client.get("/api/search", headers=_auth(), params={"org": "system"}).json()
    assert all(not r["actor"].startswith("spiffe://") for r in system["receipts"])


def test_db_org_counts(tmp_path):
    rt = _runtime(tmp_path)
    _seed_events(rt)
    counts = rt.ledger.db.org_counts()
    assert counts.get("acme", 0) >= 1 and counts.get("system", 0) >= 1
    rt.close()
