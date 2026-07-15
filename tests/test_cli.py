"""In-process tests for the `al` CLI (typer CliRunner)."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from al_core.cli.main import app

runner = CliRunner()


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_version():
    r = runner.invoke(app, ["version"])
    assert r.exit_code == 0
    assert "al-core" in r.stdout


def test_check_valid_config(workspace):
    cfg = workspace / "c.yaml"
    cfg.write_text("mode: balanced\n", encoding="utf-8")
    r = runner.invoke(app, ["check", "--config", str(cfg)])
    assert r.exit_code == 0
    assert "config OK" in r.stdout


def test_check_invalid_config_exits_nonzero(workspace):
    cfg = workspace / "c.yaml"
    cfg.write_text("mode: nope\n", encoding="utf-8")
    r = runner.invoke(app, ["check", "--config", str(cfg)])
    assert r.exit_code == 1


def test_keygen_and_force(workspace):
    r = runner.invoke(app, ["keygen", "--path", "keys/k_ed25519"])
    assert r.exit_code == 0
    assert (workspace / "keys/k_ed25519").exists()
    # Second time without --force refuses.
    r2 = runner.invoke(app, ["keygen", "--path", "keys/k_ed25519"])
    assert r2.exit_code == 1
    # With --force it rotates.
    r3 = runner.invoke(app, ["keygen", "--path", "keys/k_ed25519", "--force"])
    assert r3.exit_code == 0


def test_identity_issue_and_list(workspace):
    r = runner.invoke(app, ["identity", "issue", "acme", "claude-code"])
    assert r.exit_code == 0
    assert "spiffe://acme/agent/claude-code" in r.stdout

    r2 = runner.invoke(app, ["identity", "list"])
    assert r2.exit_code == 0
    assert "spiffe://acme/agent/claude-code" in r2.stdout

    # Duplicate issue is refused.
    r3 = runner.invoke(app, ["identity", "issue", "acme", "claude-code"])
    assert r3.exit_code == 1


def test_identity_list_empty(workspace):
    r = runner.invoke(app, ["identity", "list"])
    assert r.exit_code == 0
    assert "no identities" in r.stdout


def test_init_healthz_verify_end_to_end(workspace):
    r = runner.invoke(app, ["init"])
    assert r.exit_code == 0, r.stdout
    assert (workspace / ".env").exists()
    assert (workspace / "keys/mediator_ed25519").exists()

    h = runner.invoke(app, ["healthz"])
    assert h.exit_code == 0, h.stdout
    assert '"status": "healthy"' in h.stdout
    assert (workspace / "data/ledger.jsonl").exists()

    v = runner.invoke(app, ["verify-receipt", "data/ledger.jsonl"])
    assert v.exit_code == 0, v.stdout
