"""Phase 6 — multi-org governance: tenancy, RBAC, budgets, attestation.

Acceptance:
  * two+ orgs isolated; one org's operator cannot see another's events;
  * signed org posture attestation verifies independently;
  * 10-user multi-tenant operation, zero cross-tenant leakage.

The isolation tests are deliberately exhaustive across *every* read endpoint —
a tenancy bug that only leaks through one forgotten route is still a breach.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from al_core.principal import CAPABILITIES, Principal
from al_governance.app import create_governed_app
from al_governance.attestation import build_attestation, evidence_level
from al_governance.billing import OrgBudget, OrgBudgetLedger, cost_report
from al_governance.cli import app as gov_cli
from al_governance.tenancy import OrgStore
from al_core.runtime import Runtime
from al_verify.verify import load_public_key, verify_attestation

runner = CliRunner()

ACME_AGENT = "spiffe://acme/agent/bot"
GLOBEX_AGENT = "spiffe://globex/agent/bot"

# Every read endpoint that could leak another tenant's evidence.
READ_ENDPOINTS = [
    "/api/summary",
    "/api/receipts",
    "/api/search",
    "/api/trends",
    "/api/chain",
    "/api/session",
    "/api/orgs",
    "/api/cost",
]


def _seed(runtime: Runtime) -> None:
    """Two tenants' worth of receipts, plus a system-actor one."""
    for i in range(3):
        runtime.record(actor=ACME_AGENT, action="fetch",
                       target=f"https://acme.example/{i}", verdict="allow")
    runtime.record(actor=ACME_AGENT, action="mcp_tool_call", target="tool:exec_shell",
                   verdict="block", block_reason="TOOL_DENIED",
                   findings=[{"scanner": "tool_policy", "rule_id": "policy.deny",
                              "severity": "high", "owasp": "ASI03"}])
    for i in range(2):
        runtime.record(actor=GLOBEX_AGENT, action="fetch",
                       target=f"https://globex.example/secret-{i}", verdict="allow")
    runtime.record(actor=GLOBEX_AGENT, action="llm_call", target="openai:/v1/messages",
                   verdict="block", block_reason="INJECTION_BLOCKED",
                   findings=[{"scanner": "injection", "rule_id": "injection.override",
                              "severity": "critical", "owasp": "ASI01"}])


@pytest.fixture
def gov(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("mode: balanced\n", encoding="utf-8")
    store = OrgStore(tmp_path / "orgs.json")
    store.create_org("acme")
    store.create_org("globex")
    tokens = {
        "acme_admin": store.add_user("admin@acme", org="acme", role="admin").token,
        "acme_op": store.add_user("op@acme", org="acme", role="operator").token,
        "acme_viewer": store.add_user("viewer@acme", org="acme", role="viewer").token,
        "globex_op": store.add_user("op@globex", org="globex", role="operator").token,
        "fleet": store.add_user("root", org=None, role="admin").token,
    }
    app = create_governed_app(cfg, data_dir=tmp_path / "data",
                              store_path=tmp_path / "orgs.json")
    runtime = app.state.runtime
    _seed(runtime)
    with TestClient(app) as client:
        yield client, runtime, tokens, store


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# -- authentication -------------------------------------------------------------

def test_unauthenticated_is_denied_everywhere(gov):
    client, *_ = gov
    for path in READ_ENDPOINTS:
        assert client.get(path).status_code == 401, path


def test_unknown_token_is_denied(gov):
    client, *_ = gov
    assert client.get("/api/summary", headers=auth("alg_bogus")).status_code == 401


def test_revoked_user_stops_authenticating(gov):
    client, _, tokens, store = gov
    assert client.get("/api/summary", headers=auth(tokens["acme_op"])).status_code == 200
    store.revoke("op@acme")
    # a fresh app reads the same store file
    assert store.authenticate(tokens["acme_op"]) is None


# -- the headline: two orgs, zero leakage ----------------------------------------

def test_operator_cannot_see_another_orgs_events(gov):
    client, _, tokens, _ = gov
    r = client.get("/api/receipts", headers=auth(tokens["acme_op"])).json()
    actors = {x["actor"] for x in r["receipts"]}
    assert actors == {ACME_AGENT}
    assert "globex" not in json.dumps(r)

    g = client.get("/api/receipts", headers=auth(tokens["globex_op"])).json()
    assert {x["actor"] for x in g["receipts"]} == {GLOBEX_AGENT}
    assert "acme" not in json.dumps(g)


def test_no_endpoint_leaks_another_orgs_data(gov):
    """The exhaustive sweep: acme's operator must never see the string 'globex'
    (nor globex's block reason) anywhere in any read endpoint's response."""
    client, _, tokens, _ = gov
    for path in READ_ENDPOINTS:
        body = client.get(path, headers=auth(tokens["acme_op"])).text
        assert "globex" not in body, f"{path} leaked the other tenant"
        assert "INJECTION_BLOCKED" not in body, f"{path} leaked the other tenant's block"


def test_summary_counts_are_org_scoped(gov):
    client, _, tokens, _ = gov
    acme = client.get("/api/summary", headers=auth(tokens["acme_op"])).json()
    globex = client.get("/api/summary", headers=auth(tokens["globex_op"])).json()
    fleet = client.get("/api/summary", headers=auth(tokens["fleet"])).json()
    assert acme["events"] == 4 and globex["events"] == 3
    assert acme["orgs"] == {"acme": 4} and globex["orgs"] == {"globex": 3}
    # the fleet admin sees everything (plus the mediator's own config receipt)
    assert fleet["events"] >= 7 and {"acme", "globex"} <= set(fleet["orgs"])


def test_org_filter_cannot_widen_scope(gov):
    """?org=globex from an acme principal must not escape acme."""
    client, _, tokens, _ = gov
    r = client.get("/api/search", params={"org": "globex"},
                   headers=auth(tokens["acme_op"])).json()
    assert r["count"] == 0 and r["receipts"] == []


def test_direct_seq_fetch_of_another_org_is_not_found(gov):
    """A cross-tenant receipt must 404 — not 403, and never its content: even
    confirming the seq exists is a leak."""
    client, runtime, tokens, _ = gov
    globex_seq = next(r["seq"] for r in runtime.ledger.db.recent_filtered(limit=50)
                      if r["actor"] == GLOBEX_AGENT)
    r = client.get(f"/api/receipts/{globex_seq}", headers=auth(tokens["acme_op"]))
    assert r.status_code == 404 and "globex" not in r.text
    v = client.get(f"/api/verify/{globex_seq}", headers=auth(tokens["acme_op"]))
    assert v.status_code == 404
    # the owner can read + verify it
    own = client.get(f"/api/receipts/{globex_seq}", headers=auth(tokens["globex_op"]))
    assert own.status_code == 200 and own.json()["actor"] == GLOBEX_AGENT
    assert client.get(f"/api/verify/{globex_seq}",
                      headers=auth(tokens["globex_op"])).json()["verified"] is True


def test_trends_are_org_scoped(gov):
    client, _, tokens, _ = gov
    acme = client.get("/api/trends", headers=auth(tokens["acme_op"])).json()["series"]
    globex = client.get("/api/trends", headers=auth(tokens["globex_op"])).json()["series"]
    assert sum(b["total"] for b in acme) == 4
    assert sum(b["total"] for b in globex) == 3


def test_org_list_is_tenant_scoped(gov):
    client, _, tokens, _ = gov
    acme = client.get("/api/orgs", headers=auth(tokens["acme_op"])).json()["orgs"]
    assert [o["org"] for o in acme] == ["acme"]
    fleet = client.get("/api/orgs", headers=auth(tokens["fleet"])).json()["orgs"]
    assert [o["org"] for o in fleet] == ["acme", "globex"]


# -- RBAC ------------------------------------------------------------------------

def test_role_capabilities(gov):
    client, _, tokens, _ = gov
    s = client.get("/api/session", headers=auth(tokens["acme_viewer"])).json()
    assert s["role"] == "viewer" and s["org"] == "acme"
    assert s["capabilities"] == CAPABILITIES["viewer"]
    assert "approve" not in s["capabilities"] and "configure" not in s["capabilities"]


def test_viewer_cannot_configure_or_attest(gov):
    client, _, tokens, _ = gov
    assert client.post("/api/killswitch", json={},
                       headers=auth(tokens["acme_viewer"])).status_code == 403
    assert client.get("/api/users",
                      headers=auth(tokens["acme_viewer"])).status_code == 403
    assert client.get("/api/attestation",
                      headers=auth(tokens["acme_op"])).status_code == 403  # operator too


def test_admin_can_configure_and_attest(gov):
    client, _, tokens, _ = gov
    assert client.post("/api/killswitch", json={"reason": "drill"},
                       headers=auth(tokens["acme_admin"])).json()["engaged"]
    client.post("/api/killswitch", json={"engage": False}, headers=auth(tokens["acme_admin"]))
    assert client.get("/api/attestation",
                      headers=auth(tokens["acme_admin"])).status_code == 200


def test_users_endpoint_never_returns_token_hashes(gov):
    client, _, tokens, _ = gov
    body = client.get("/api/users", headers=auth(tokens["acme_admin"])).text
    assert "token_hash" not in body and "sha256:" not in body


def test_fleet_scope_is_admin_only(tmp_path):
    store = OrgStore(tmp_path / "orgs.json")
    with pytest.raises(ValueError, match="admin-only"):
        store.add_user("sneaky", org=None, role="operator")


def test_user_in_unknown_org_is_rejected(tmp_path):
    store = OrgStore(tmp_path / "orgs.json")
    with pytest.raises(ValueError, match="no such org"):
        store.add_user("x@nope", org="nope", role="viewer")


# -- 10-user multi-tenant operation ------------------------------------------------

def test_ten_users_across_orgs_zero_leakage(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("mode: balanced\n", encoding="utf-8")
    store = OrgStore(tmp_path / "orgs.json")
    orgs = ["acme", "globex", "initech"]
    for o in orgs:
        store.create_org(o)

    users = []  # 10 users: 3 orgs x 3 roles + 1 fleet admin
    for o in orgs:
        for role in ("admin", "operator", "viewer"):
            users.append((o, role, store.add_user(f"{role}@{o}", org=o, role=role).token))
    users.append((None, "admin", store.add_user("root", org=None, role="admin").token))
    assert len(users) == 10

    app = create_governed_app(cfg, data_dir=tmp_path / "data",
                              store_path=tmp_path / "orgs.json")
    runtime = app.state.runtime
    for o in orgs:
        for i in range(4):
            runtime.record(actor=f"spiffe://{o}/agent/bot", action="fetch",
                           target=f"https://{o}.example/{i}", verdict="allow")

    with TestClient(app) as client:
        for org, role, token in users:
            for path in READ_ENDPOINTS:
                body = client.get(path, headers=auth(token)).text
                if org is None:
                    continue  # fleet admin legitimately sees all
                for other in (x for x in orgs if x != org):
                    assert other not in body, f"{role}@{org} leaked {other} via {path}"
            if org is not None:
                summary = client.get("/api/summary", headers=auth(token)).json()
                assert summary["events"] == 4 and summary["orgs"] == {org: 4}


# -- attestation --------------------------------------------------------------------

def test_attestation_verifies_independently(gov, tmp_path):
    _, runtime, _, _ = gov
    doc = build_attestation(runtime, "acme")
    # signed with the mediator key; verified by the STANDALONE verifier
    pub = load_public_key(runtime.settings.keys.signing_key_path.read_bytes()
                          if False else _pubkey_bytes(runtime))
    assert verify_attestation(doc, pub) == doc["record_hash"]

    # its content is org-scoped and derived, not asserted
    assert doc["org"] == "acme"
    assert doc["evidence"]["events"] == 4
    assert doc["evidence"]["blocks"] == 1
    assert doc["evidence"]["asi_findings"] == {"ASI03": 1}
    assert "globex" not in json.dumps(doc)
    assert doc["chain"]["verified"] is True and doc["chain"]["head"].startswith("sha256:")
    assert doc["evidence_level"] in ("AEL-2", "AEL-3")


def _pubkey_bytes(runtime):
    from al_core.keys import public_key_hex

    return public_key_hex(runtime.public_key)


def test_attestation_tamper_is_detected(gov):
    _, runtime, _, _ = gov
    doc = build_attestation(runtime, "acme")
    doc["evidence"]["blocks"] = 0  # a tenant "improves" its posture
    with pytest.raises(Exception):
        verify_attestation(doc, load_public_key(_pubkey_bytes(runtime)))


def test_evidence_level_ladder():
    assert evidence_level(chain_verified=False, enforcing=True, self_test=True) == "AEL-0"
    assert evidence_level(chain_verified=True, enforcing=False, self_test=True) == "AEL-1"
    assert evidence_level(chain_verified=True, enforcing=True, self_test=False) == "AEL-2"
    assert evidence_level(chain_verified=True, enforcing=True, self_test=True) == "AEL-3"


def test_audit_mode_cannot_claim_enforcement_level(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("mode: audit\n", encoding="utf-8")
    rt = Runtime(cfg, data_dir=tmp_path / "data")
    rt.record(actor=ACME_AGENT, action="fetch", target="https://x", verdict="allow")
    doc = build_attestation(rt, "acme")
    assert doc["posture"]["enforcing"] is False
    assert doc["evidence_level"] == "AEL-1"  # observing, not enforcing
    rt.close()


# -- budgets + cost ------------------------------------------------------------------

def test_org_budget_denies_over_limit(gov):
    _, runtime, _, _ = gov
    ledger = OrgBudgetLedger(runtime.ledger.db,
                             {"acme": OrgBudget("acme", max_requests_per_day=2)})
    assert ledger.try_request("acme") == (True, None)
    assert ledger.try_request("acme") == (True, None)
    ok, reason = ledger.try_request("acme")
    assert not ok and reason == "BUDGET_EXCEEDED"
    # an unbudgeted org is unaffected (budgets are opt-in limits, not policy)
    assert ledger.try_request("globex") == (True, None)


def test_org_budget_tokens_and_usage(gov):
    _, runtime, _, _ = gov
    ledger = OrgBudgetLedger(runtime.ledger.db,
                             {"acme": OrgBudget("acme", max_tokens_per_day=100)})
    assert ledger.try_request("acme", tokens=60)[0]
    assert not ledger.try_request("acme", tokens=60)[0]  # would exceed
    ledger.record_usage("acme", 500)  # post-hoc usage is never dropped
    requests, tokens = ledger.usage("acme")
    assert requests == 1 and tokens == 560


def test_org_scoped_vkey_receipts_are_visible_to_their_tenant(gov):
    """A virtual key bound to an org produces SPIFFE-shaped actors, so the LLM
    calls made with it are the tenant's *own* events — visible to that tenant's
    operator, and invisible to any other. An org-less key stays in the system
    bucket (single-tenant behaviour, unchanged)."""
    client, runtime, tokens, _ = gov
    acme_key, _ = runtime.vkeys.issue("alice", org="acme")
    legacy_key, _ = runtime.vkeys.issue("carol")

    assert acme_key.actor == "spiffe://acme/user/alice"
    assert legacy_key.actor == "user:carol"

    runtime.record(actor=acme_key.actor, action="llm_call",
                   target="openai:/v1/messages", verdict="allow")
    runtime.record(actor=legacy_key.actor, action="llm_call",
                   target="openai:/v1/messages", verdict="allow")

    acme = client.get("/api/receipts", headers=auth(tokens["acme_op"])).json()
    llm = [r for r in acme["receipts"] if r["action"] == "llm_call"]
    assert [r["actor"] for r in llm] == ["spiffe://acme/user/alice"]

    globex = client.get("/api/receipts", headers=auth(tokens["globex_op"])).text
    assert "alice" not in globex and "carol" not in globex


def test_cost_report_is_org_scoped_and_honest_about_price(gov):
    _, runtime, _, _ = gov
    runtime.vkeys.issue("alice", org="acme")
    runtime.vkeys.issue("bob", org="globex")
    acme = cost_report(runtime.ledger.db, runtime.vkeys, org="acme")
    assert [k["org"] for k in acme["keys"]] == ["acme"]
    assert acme["usd"] is None  # no rate given -> not silently zero
    priced = cost_report(runtime.ledger.db, runtime.vkeys, org="acme", usd_per_mtok=3.0)
    assert priced["usd"] == 0.0 and priced["rate_usd_per_mtok"] == 3.0
    fleet = cost_report(runtime.ledger.db, runtime.vkeys)
    assert {k["org"] for k in fleet["keys"]} == {"acme", "globex"}


# -- CLI ---------------------------------------------------------------------------

def test_cli_org_user_attest_roundtrip(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    data = ["--data-dir", str(tmp_path / "data")]

    assert runner.invoke(gov_cli, ["org", "create", "acme", *data]).exit_code == 0
    r = runner.invoke(gov_cli, ["user", "add", "alice@acme", "--org", "acme",
                                "--role", "operator", *data])
    assert r.exit_code == 0 and "alg_" in r.output      # token shown once

    r = runner.invoke(gov_cli, ["user", "list", *data])
    assert "alice@acme" in r.output and "alg_" not in r.output  # never re-shown

    # seed one receipt, then export + verify an attestation with al-verify
    rt = Runtime(None, data_dir=tmp_path / "data")
    rt.record(actor=ACME_AGENT, action="fetch", target="https://x", verdict="allow")
    rt.close()

    out = tmp_path / "attestation.json"
    r = runner.invoke(gov_cli, ["attest", "export", "acme", "-o", str(out), *data])
    assert r.exit_code == 0 and "evidence level" in r.output
    r = runner.invoke(gov_cli, ["attest", "verify", str(out),
                                "--pubkey", "keys/mediator_ed25519.pub"])
    assert r.exit_code == 0


def test_cli_rejects_duplicate_org_and_bad_role(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    data = ["--data-dir", str(tmp_path / "data")]
    runner.invoke(gov_cli, ["org", "create", "acme", *data])
    assert runner.invoke(gov_cli, ["org", "create", "acme", *data]).exit_code == 1
    r = runner.invoke(gov_cli, ["user", "add", "x@acme", "--org", "acme",
                                "--role", "wizard", *data])
    assert r.exit_code == 1 and "unknown role" in r.output


# -- the core seam stays single-tenant by default ------------------------------------

def test_core_app_without_governance_is_single_tenant_admin(tmp_path):
    """The core alone: admin token -> fleet admin, no user directory."""
    from al_core.app import create_app

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("mode: balanced\n", encoding="utf-8")
    app = create_app(cfg, data_dir=tmp_path / "data")
    with TestClient(app) as client:
        s = client.get("/api/session",
                       headers=auth("test-admin-token")).json()
        assert s["role"] == "admin" and s["org"] is None
        assert Principal("admin", "admin").can("configure")


# -- the layer boundary is a dependency direction, not a comment --------------------

def test_core_never_imports_the_governance_layer():
    """core/ must not import governance/. The boundary is only real if the
    dependency direction enforces it — and the isolation must stay enforced in
    the core, where the governance layer cannot widen it."""
    from pathlib import Path

    core = Path(__file__).resolve().parents[1] / "core"
    offenders = [
        f"{p.relative_to(core)}:{i}"
        for p in core.rglob("*.py")
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if "al_governance" in line
    ]
    assert offenders == [], f"core imports the governance layer: {offenders}"
