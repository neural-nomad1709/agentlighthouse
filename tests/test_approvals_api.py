"""HITL approvals surface (AL-0.1) — the operator side of the L4 gate.

`HitlGate` has held pending approvals since Phase 3, but nothing served them:
no endpoint, no CLI verb. These tests specify the serving surface:

  * ``GET /api/approvals`` — pending requests with actor/tool/age/deadline;
  * ``POST /api/approvals/{id}`` — allow | deny, resolving actor recorded,
    one signed receipt per resolution;
  * existing semantics preserved exactly: a timed-out request cannot be
    resolved, timeout remains a denial.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from al_core.app import create_app
from al_core.principal import Principal

TOKEN = "approvals-admin-token"
VIEWER_TOKEN = "approvals-viewer-token"

# A short HITL timeout so a "lapsed" request is cheap to produce in a test.
SHORT_TIMEOUT_YAML = "mode: balanced\npolicy:\n  hitl_timeout_s: 0.15\n"


def _authenticator(token: str | None) -> Principal | None:
    if token == TOKEN:
        return Principal(subject="alice", role="admin", org=None)
    if token == VIEWER_TOKEN:
        return Principal(subject="watcher", role="viewer", org=None)
    return None


def _make_client(tmp_path, yaml_text: str = "mode: balanced\n") -> TestClient:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(yaml_text, encoding="utf-8")
    application = create_app(
        cfg, data_dir=tmp_path / "data",
        admin_api_token=TOKEN, authenticator=_authenticator,
    )
    return TestClient(application)


def _hitl(client: TestClient):
    return client.app.state.runtime.action_gate.hitl


def _auth(token: str = TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client(tmp_path):
    with _make_client(tmp_path) as c:
        yield c


# -- listing ---------------------------------------------------------------------

def test_approvals_require_token(client):
    assert client.get("/api/approvals").status_code == 401
    assert client.post("/api/approvals/hitl_x", json={"decision": "allow"}).status_code == 401


def test_submitted_request_is_visible_with_actor_tool_age_deadline(client):
    req = _hitl(client).submit("spiffe://acme/agent/claude-code", "send_email")
    r = client.get("/api/approvals", headers=_auth())
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 1
    row = body["approvals"][0]
    assert row["request_id"] == req.request_id
    assert row["actor"] == "spiffe://acme/agent/claude-code"
    assert row["tool"] == "send_email"
    assert row["age_s"] >= 0
    assert 0 < row["remaining_s"] <= row["timeout_s"]


# -- resolution ------------------------------------------------------------------

def test_allow_resolves_and_names_the_resolving_actor(client):
    gate = _hitl(client)
    req = gate.submit("spiffe://acme/agent/claude-code", "send_email")
    r = client.post(f"/api/approvals/{req.request_id}",
                    headers=_auth(), json={"decision": "allow"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "approved"
    assert body["resolved_by"] == "user:alice"
    # the gate itself now allows the held call
    assert gate.decision(req.request_id).allowed
    # and the resolved request is no longer pending
    assert client.get("/api/approvals", headers=_auth()).json()["count"] == 0


def test_deny_resolves_to_denied(client):
    gate = _hitl(client)
    req = gate.submit("spiffe://acme/agent/claude-code", "delete_backups")
    r = client.post(f"/api/approvals/{req.request_id}",
                    headers=_auth(), json={"decision": "deny"})
    assert r.status_code == 200
    assert r.json()["status"] == "denied"
    assert not gate.decision(req.request_id).allowed


def test_resolution_emits_one_verifiable_receipt(client):
    gate = _hitl(client)
    req = gate.submit("spiffe://acme/agent/claude-code", "send_email")
    before = client.get("/api/receipts", headers=_auth(),
                        params={"actor": "user:alice"}).json()["count"]
    client.post(f"/api/approvals/{req.request_id}",
                headers=_auth(), json={"decision": "allow"})
    receipts = client.get("/api/receipts", headers=_auth(),
                          params={"actor": "user:alice"}).json()
    assert receipts["count"] == before + 1
    resolution = next(
        r for r in receipts["receipts"] if r["target"] == f"hitl:{req.request_id}"
    )
    assert resolution["actor"] == "user:alice"
    assert resolution["verdict"] == "allow"
    # verified by the same standalone verifier third parties run
    v = client.get(f"/api/verify/{resolution['seq']}", headers=_auth()).json()
    assert v["verified"] is True, v


def test_denial_receipt_carries_block_verdict(client):
    gate = _hitl(client)
    req = gate.submit("spiffe://acme/agent/claude-code", "delete_backups")
    client.post(f"/api/approvals/{req.request_id}",
                headers=_auth(), json={"decision": "deny"})
    receipts = client.get("/api/receipts", headers=_auth(),
                          params={"actor": "user:alice"}).json()["receipts"]
    resolution = next(r for r in receipts if r["target"] == f"hitl:{req.request_id}")
    assert resolution["verdict"] == "block"
    assert resolution["block_reason"] == "HITL_DENIED"


# -- guardrails --------------------------------------------------------------------

def test_viewer_cannot_resolve(client):
    req = _hitl(client).submit("spiffe://acme/agent/claude-code", "send_email")
    r = client.post(f"/api/approvals/{req.request_id}",
                    headers=_auth(VIEWER_TOKEN), json={"decision": "allow"})
    assert r.status_code == 403
    # nothing changed
    assert _hitl(client).status(req.request_id) == "pending"


def test_unknown_request_is_404(client):
    r = client.post("/api/approvals/hitl_deadbeef",
                    headers=_auth(), json={"decision": "allow"})
    assert r.status_code == 404


def test_bad_decision_value_is_rejected(client):
    req = _hitl(client).submit("a", "send_email")
    r = client.post(f"/api/approvals/{req.request_id}",
                    headers=_auth(), json={"decision": "maybe"})
    assert r.status_code == 422
    assert _hitl(client).status(req.request_id) == "pending"


def test_double_resolution_conflicts(client):
    req = _hitl(client).submit("a", "send_email")
    first = client.post(f"/api/approvals/{req.request_id}",
                        headers=_auth(), json={"decision": "allow"})
    assert first.status_code == 200
    second = client.post(f"/api/approvals/{req.request_id}",
                         headers=_auth(), json={"decision": "deny"})
    assert second.status_code == 409
    assert _hitl(client).status(req.request_id) == "approved"


def test_lapsed_request_cannot_be_resolved_and_is_not_listed(tmp_path):
    with _make_client(tmp_path, SHORT_TIMEOUT_YAML) as client:
        gate = _hitl(client)
        req = gate.submit("spiffe://acme/agent/claude-code", "send_email")
        time.sleep(0.2)  # > hitl_timeout_s: the request lapses
        assert client.get("/api/approvals", headers=_auth()).json()["count"] == 0
        r = client.post(f"/api/approvals/{req.request_id}",
                        headers=_auth(), json={"decision": "allow"})
        assert r.status_code == 409
        # timeout remains a denial
        assert gate.status(req.request_id) == "timed_out"
        assert not gate.decision(req.request_id).allowed
