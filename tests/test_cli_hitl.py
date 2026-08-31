"""``al hitl`` — resolve pending approvals from the terminal (AL-0.1).

Approvals live in the serving process's memory, so unlike most ``al`` verbs
(which boot their own Runtime) these are HTTP clients of the running control
plane. The tests wire the real CLI to the real app over httpx's ASGI
transport — no live socket, no mocked handlers.
"""

from __future__ import annotations

import json

import httpx
import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from al_core.app import create_app
from al_core.cli import main as cli_main

TOKEN = "hitl-cli-token"


@pytest.fixture
def control_plane(tmp_path, monkeypatch):
    """A live app + a CLI wired to it; returns (app, hitl_gate)."""
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("mode: balanced\n", encoding="utf-8")
    application = create_app(cfg, data_dir=tmp_path / "data", admin_api_token=TOKEN)

    def client_factory(url: str, token: str) -> httpx.Client:
        assert token == TOKEN
        client = TestClient(application)  # an httpx.Client speaking ASGI
        client.headers["Authorization"] = f"Bearer {token}"
        return client

    monkeypatch.setattr(cli_main, "_hitl_client", client_factory)
    yield application, application.state.runtime.action_gate.hitl


def _run(*args: str):
    return CliRunner().invoke(
        cli_main.app, ["hitl", *args, "--token", TOKEN]
    )


def test_list_shows_a_pending_request(control_plane):
    _, gate = control_plane
    req = gate.submit("spiffe://acme/agent/claude-code", "send_email")
    result = _run("list")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["count"] == 1
    assert payload["approvals"][0]["request_id"] == req.request_id
    assert payload["approvals"][0]["tool"] == "send_email"


def test_approve_resolves_the_request(control_plane):
    _, gate = control_plane
    req = gate.submit("spiffe://acme/agent/claude-code", "send_email")
    result = _run("approve", req.request_id)
    assert result.exit_code == 0, result.output
    assert gate.status(req.request_id) == "approved"


def test_deny_resolves_the_request(control_plane):
    _, gate = control_plane
    req = gate.submit("spiffe://acme/agent/claude-code", "delete_backups")
    result = _run("deny", req.request_id)
    assert result.exit_code == 0, result.output
    assert gate.status(req.request_id) == "denied"


def test_resolving_an_unknown_request_fails_clearly(control_plane):
    result = _run("approve", "hitl_deadbeef")
    assert result.exit_code == 1
    assert "not_found" in result.output or "404" in result.output
