"""Held approvals carry what is being approved, and for whom.

Approving "install-package" by name is not informed consent: the request
carries a ``detail`` (the fully rendered commands, for a remote-exec host) and
the ``session`` it belongs to, both persisted, both surfaced wherever a human
resolves — otherwise an embedder cannot re-associate a rehydrated request with
the run that filed it.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from al_core.app import create_app
from al_core.capability.hitl import HitlGate
from al_core.capability.store import CapabilityStore

TOKEN = "hitl-detail-token"
COMMANDS = "  [install] apt-get install -y myapp\n  [verify] dpkg -l myapp"


def test_submit_records_detail_and_session():
    gate = HitlGate(timeout_s=100.0)
    req = gate.submit("spiffe://x/agent/a", "install-package",
                      detail=COMMANDS, session="SES-1")
    assert req.detail == COMMANDS
    assert req.session == "SES-1"


def test_detail_and_session_survive_a_restart(tmp_path):
    store_path = tmp_path / "capability_state.db"
    gate = HitlGate(timeout_s=100.0, store=CapabilityStore(store_path))
    req = gate.submit("spiffe://x/agent/a", "install-package",
                      detail=COMMANDS, session="SES-1")

    gate2 = HitlGate(timeout_s=100.0, store=CapabilityStore(store_path))
    rehydrated = gate2.request(req.request_id)
    assert rehydrated is not None
    assert rehydrated.detail == COMMANDS
    assert rehydrated.session == "SES-1"


def test_the_approvals_api_shows_what_is_being_approved(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("mode: balanced\n", encoding="utf-8")
    application = create_app(cfg, data_dir=tmp_path / "data", admin_api_token=TOKEN)
    with TestClient(application) as client:
        gate = application.state.runtime.action_gate.hitl
        gate.submit("spiffe://x/agent/a", "install-package",
                    detail=COMMANDS, session="SES-1")
        rows = client.get(
            "/api/approvals", headers={"Authorization": f"Bearer {TOKEN}"}
        ).json()["approvals"]
        assert rows[0]["detail"] == COMMANDS
        assert rows[0]["session"] == "SES-1"


def test_submit_without_detail_still_works():
    gate = HitlGate(timeout_s=100.0)
    req = gate.submit("spiffe://x/agent/a", "send_email")
    assert req.detail is None and req.session is None
    assert gate.approve(req.request_id)
