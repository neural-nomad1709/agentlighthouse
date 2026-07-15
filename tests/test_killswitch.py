"""Phase 5 — kill switch (L6/ops): >=3 sources, full deny-all, receipted.

Acceptance: kill switch from each source -> full
deny-all; agent-facing surface exposes no control endpoints (in-process half
of the segregation proof — the topology half lives in compose/selftest).
"""

from __future__ import annotations

import json
import signal

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from al_core.app import create_app
from al_core.capability.gate import ActionGate
from al_core.capability.policy import ToolPolicy
from al_core.cli.main import app as cli
from al_core.gateway.decision import BlockReason
from al_core.gateway.web import create_gateway_app
from al_core.killswitch import SENTINEL_NAME, KillSwitch
from al_core.runtime import Runtime

runner = CliRunner()
TOKEN = "test-admin-token"  # from the conftest AL_ADMIN_API_TOKEN fixture


class Rec:
    def __init__(self): self.calls = []
    def __call__(self, **kw): self.calls.append(kw)


def _runtime(tmp_path) -> Runtime:
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("mode: balanced\n", encoding="utf-8")
    return Runtime(cfg, data_dir=tmp_path / "data")


# -- core mechanism ---------------------------------------------------------------

def test_engage_disengage_lifecycle_receipted(tmp_path):
    rec = Rec()
    ks = KillSwitch(tmp_path, recorder=rec)
    assert not ks.engaged() and not ks.status()["engaged"]

    status = ks.engage("cli", reason="incident 42")
    assert status["engaged"] and status["source"] == "cli" and status["reason"] == "incident 42"
    assert ks.engaged()
    # engage receipted once, critical, even when called twice (idempotent)
    ks.engage("cli", reason="incident 42")
    engages = [c for c in rec.calls if c["verdict"] == "block"]
    assert len(engages) == 1
    assert engages[0]["action"] == "killswitch"
    assert engages[0]["block_reason"] == BlockReason.KILLSWITCH_ENGAGED
    assert engages[0]["findings"][0]["severity"] == "critical"

    assert not ks.disengage()["engaged"]
    assert not ks.engaged()
    assert rec.calls[-1]["verdict"] == "allow"


def test_sentinel_touched_out_of_band_engages_and_receipts_once(tmp_path):
    rec = Rec()
    ks = KillSwitch(tmp_path, recorder=rec)
    (tmp_path / SENTINEL_NAME).touch()  # any process/human with filesystem access
    assert ks.engaged() and ks.engaged()  # second check must not re-receipt
    assert len(rec.calls) == 1 and rec.calls[0]["target"] == "killswitch:sentinel"
    assert ks.status()["source"] == "sentinel"


def test_engagement_survives_restart(tmp_path):
    KillSwitch(tmp_path).engage("cli")
    assert KillSwitch(tmp_path).engaged()  # a fresh process still denies


def test_signal_source_posix_only(tmp_path):
    ks = KillSwitch(tmp_path)
    installed = ks.install_signal_handler()
    assert installed == hasattr(signal, "SIGUSR1")


# -- enforcement: every ingress denies ------------------------------------------------

def test_gateway_deny_all_when_engaged(tmp_path):
    runtime = _runtime(tmp_path)
    app = create_gateway_app(runtime)
    with TestClient(app) as client:
        runtime.killswitch.engage("api", reason="drill")
        for path, kwargs in [
            ("/fetch", {"params": {"url": "https://api.example.com/x"}}),
            ("/v1/chat/completions", {}),
            ("/v1/messages", {}),
        ]:
            r = client.get(path, **kwargs) if path == "/fetch" else client.post(path, json={})
            assert r.status_code == 503, path
            assert r.headers["x-al-block-reason"] == BlockReason.KILLSWITCH_ENGAGED

        # /healthz stays answerable during the incident
        assert client.get("/healthz").status_code == 200

        # disengage -> traffic flows again (blocked later by policy, not 503)
        runtime.killswitch.disengage()
        r = client.get("/fetch", params={"url": "https://api.example.com/x"})
        assert r.status_code != 503
    runtime.close()


def test_action_gate_denies_when_engaged(tmp_path):
    engaged = {"on": False}
    gate = ActionGate(
        ToolPolicy.from_dict({"agents": {"a": {"allow": [{"tool": "read_file"}]}}}),
        killswitch=lambda: engaged["on"],
    )
    assert gate.authorize("a", "read_file", {}).allowed
    engaged["on"] = True
    out = gate.authorize("a", "read_file", {})
    assert not out.allowed
    assert out.decision.block_reason == BlockReason.KILLSWITCH_ENGAGED


def test_runtime_boots_denying_when_previously_engaged(tmp_path):
    rt = _runtime(tmp_path)
    rt.killswitch.engage("cli")
    rt.close()
    rt2 = Runtime(tmp_path / "cfg.yaml", data_dir=tmp_path / "data")
    assert rt2.killswitch.engaged()
    out = rt2.action_gate.authorize("spiffe://acme/agent/x", "read_file", {})
    assert out.decision.block_reason == BlockReason.KILLSWITCH_ENGAGED
    rt2.close()


# -- sources: control API + CLI --------------------------------------------------------

def test_control_api_engage_disengage(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("mode: balanced\n", encoding="utf-8")
    app = create_app(cfg, data_dir=tmp_path / "data")
    with TestClient(app) as client:
        auth = {"Authorization": f"Bearer {TOKEN}"}
        assert client.post("/api/killswitch", json={}).status_code == 401  # token required

        r = client.post("/api/killswitch", json={"reason": "compromise"}, headers=auth)
        assert r.status_code == 200 and r.json()["engaged"] and r.json()["source"] == "api"
        assert client.get("/api/killswitch", headers=auth).json()["engaged"]

        r = client.post("/api/killswitch", json={"engage": False}, headers=auth)
        assert not r.json()["engaged"]


def test_cli_engage_status_disengage(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    data = ["--data-dir", str(tmp_path / "data")]
    assert runner.invoke(cli, ["killswitch", "engage", "--reason", "drill", *data]).exit_code == 0
    assert runner.invoke(cli, ["killswitch", "status", *data]).exit_code == 3
    assert runner.invoke(cli, ["killswitch", "disengage", *data]).exit_code == 0
    assert runner.invoke(cli, ["killswitch", "status", *data]).exit_code == 0


# -- receipts verify + segregation (in-process half) -----------------------------------

def test_killswitch_receipts_verify(tmp_path):
    rt = _runtime(tmp_path)
    rt.killswitch.engage("api", actor="operator:api", reason="drill")
    rt.killswitch.disengage(actor="operator:api")
    assert rt.ledger.verify(rt.public_key) >= 2
    recent = rt.ledger.db.recent_filtered(action="killswitch")
    assert {r["verdict"] for r in recent} == {"block", "allow"}
    rt.close()


def test_control_plane_engages_data_plane_via_shared_sentinel(tmp_path):
    """The compose topology in one process: the control plane and the data
    plane share ONLY a sentinel directory (a file on a volume), never a network
    path. An operator on control-net drills the data plane to deny-all without
    any route existing from agent-net to the control plane."""
    sentinel_dir = tmp_path / "killswitch"       # the shared volume
    control_dir = tmp_path / "control-data"      # control-plane ledger
    data_dir = tmp_path / "data"                 # data-plane ledger

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        f"mode: balanced\ncontrol:\n  killswitch_dir: {sentinel_dir.as_posix()}\n",
        encoding="utf-8")

    control = Runtime(cfg, data_dir=control_dir)   # "al-control" on control-net
    data = Runtime(cfg, data_dir=data_dir)         # "al-core" on agent-net+egress

    # An identity the shipped policy allows — the baseline is a working plane.
    agent, tool, args = "spiffe://acme/agent/claude-code", "read_file", {"path": "/workspace/a.py"}
    assert data.action_gate.authorize(agent, tool, args).allowed

    control.killswitch.engage("api", actor="operator:api", reason="incident")

    # The data plane sees it — different process, different ledger, no network.
    assert data.killswitch.engaged()
    out = data.action_gate.authorize(agent, tool, args)
    assert out.decision.block_reason == BlockReason.KILLSWITCH_ENGAGED

    # Each plane's own evidence chain stays valid and separately verifiable.
    assert control.ledger.verify(control.public_key) >= 1
    assert data.ledger.verify(data.public_key) >= 1
    # The data plane receipted the engagement it discovered via the sentinel.
    assert data.ledger.db.recent_filtered(action="killswitch", verdict="block")

    control.killswitch.disengage()
    assert not data.killswitch.engaged()
    assert data.action_gate.authorize(agent, tool, args).allowed  # plane resumes
    data.close()
    control.close()


def test_gateway_exposes_no_control_surface(tmp_path):
    """The agent-facing app must not mount admin/evidence/kill-switch routes.

    The other half of this proof is topology (agent-net cannot route to the
    control plane) — asserted live by the compose selftest probes."""
    runtime = _runtime(tmp_path)
    app = create_gateway_app(runtime)
    with TestClient(app) as client:
        for path in ("/api/killswitch", "/api/summary", "/api/receipts",
                     "/api/search", "/dashboard"):
            got = client.get(path)
            assert got.status_code in (404, 405), path
            post = client.post(path, json={})
            assert post.status_code in (404, 405), path
    runtime.close()
