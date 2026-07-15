"""CLI surface added in Phase 1: vkey, egress, gateway lifespan wiring."""

from __future__ import annotations

import httpx
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from al_core.cli.main import app
from al_core.egress import selftest
from al_core.gateway.web import create_gateway_app
from al_core.runtime import Runtime

runner = CliRunner()


# -- al vkey ---------------------------------------------------------------------

def test_vkey_issue_list_revoke_roundtrip(tmp_path):
    r = runner.invoke(
        app,
        ["vkey", "issue", "alice", "--max-requests", "100", "--data-dir", str(tmp_path)],
    )
    assert r.exit_code == 0 and "alk_" in r.stdout
    key_id = next(w for w in r.stdout.split() if w.startswith("vk_"))

    r = runner.invoke(app, ["vkey", "list", "--data-dir", str(tmp_path)])
    assert key_id in r.stdout and "active" in r.stdout
    assert "alk_" not in r.stdout  # key material never listed

    r = runner.invoke(app, ["vkey", "revoke", key_id, "--data-dir", str(tmp_path)])
    assert r.exit_code == 0
    r = runner.invoke(app, ["vkey", "list", "--data-dir", str(tmp_path)])
    assert "revoked" in r.stdout


def test_vkey_revoke_unknown_fails(tmp_path):
    r = runner.invoke(app, ["vkey", "revoke", "vk_none", "--data-dir", str(tmp_path)])
    assert r.exit_code == 1


# -- al egress ---------------------------------------------------------------------

def test_egress_selftest_healthy_when_probes_refused(monkeypatch):
    def refuse(addr, timeout, source_address=None):
        raise OSError("no route")

    monkeypatch.setattr(selftest, "_default_connect", refuse)
    r = runner.invoke(app, ["egress", "selftest"])
    assert r.exit_code == 0
    assert "choke-point holds" in r.stdout


def test_egress_selftest_detects_bypass(monkeypatch):
    class Sock:
        def close(self) -> None:
            pass

    monkeypatch.setattr(selftest, "_default_connect", lambda a, t, s=None: Sock())
    r = runner.invoke(app, ["egress", "selftest"])
    assert r.exit_code == 1
    assert "CRITICAL" in r.output


def test_egress_nftables_renders():
    r = runner.invoke(app, ["egress", "nftables", "--al-core-ip", "172.28.0.2"])
    assert r.exit_code == 0
    assert "policy drop;" in r.stdout and "172.28.0.2" in r.stdout


# -- gateway lifespan wires the forward proxy ---------------------------------------

def test_gateway_app_starts_forward_proxy(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("mode: balanced\n", encoding="utf-8")
    runtime = Runtime(cfg, data_dir=tmp_path / "data")
    gw = create_gateway_app(
        runtime,
        transport=httpx.MockTransport(lambda r: httpx.Response(200)),
        forward_listen="127.0.0.1:0",  # ephemeral port
    )
    with TestClient(gw):
        proxy = gw.state.forward_proxy
        assert proxy.bound_port > 0
    runtime.close()
