"""Phase 5 — SIEM export: receipts as flat, MITRE-tagged, verifiable events."""

from __future__ import annotations

import io
import json

from typer.testing import CliRunner

from al_core.audit.siem import export, to_event
from al_core.cli.main import app
from al_core.gateway.decision import BlockReason
from al_core.runtime import Runtime

runner = CliRunner()

BLOCK = {
    "v": 1, "seq": 7, "ts": "2026-07-11T12:00:00.000Z",
    "actor": "spiffe://acme/agent/bot", "action": "mcp_tool_result",
    "target": "tool:web_search:result", "verdict": "block",
    "block_reason": BlockReason.INJECTION_BLOCKED,
    "findings": [
        {"scanner": "injection", "rule_id": "injection.override", "severity": "critical",
         "owasp": "ASI01", "mitre": "T1204"},
        {"scanner": "entropy", "rule_id": "entropy.blob", "severity": "low", "owasp": "ASI08"},
    ],
    "prev_hash": "sha256:aa", "record_hash": "sha256:bb", "sig": "ed25519:cc",
}


def test_block_event_is_alert_with_mitre_and_owasp():
    e = to_event(BLOCK)
    assert e["@timestamp"] == BLOCK["ts"]
    assert e["event"]["kind"] == "alert" and e["event"]["outcome"] == "failure"
    assert e["event"]["action"] == "mcp_tool_result" and e["event"]["sequence"] == 7
    assert e["event"]["severity"] == "critical"  # strongest finding wins
    assert e["user"]["id"] == "spiffe://acme/agent/bot"
    assert e["threat"]["technique"]["id"] == ["T1204"]
    assert e["al"]["owasp"] == ["ASI01", "ASI08"]
    assert e["al"]["block_reason"] == BlockReason.INJECTION_BLOCKED
    assert e["al"]["rules"] == ["injection/injection.override", "entropy/entropy.blob"]


def test_event_carries_verification_pointers():
    e = to_event(BLOCK)
    assert e["al"]["record_hash"] == "sha256:bb"
    assert e["al"]["prev_hash"] == "sha256:aa"
    assert e["al"]["sig"] == "ed25519:cc"


def test_allow_event_is_not_an_alert_and_has_no_threat_block():
    e = to_event({"seq": 1, "ts": "2026-07-11T12:00:00.000Z", "actor": "a",
                  "action": "fetch", "target": "https://x", "verdict": "allow",
                  "findings": []})
    assert e["event"]["kind"] == "event" and e["event"]["outcome"] == "success"
    assert e["event"]["severity"] == "low"
    assert "threat" not in e


def test_strip_event_reports_redaction_counts_not_plaintext():
    e = to_event({"seq": 2, "ts": "2026-07-11T12:00:00.000Z", "actor": "a",
                  "action": "fetch", "target": "https://x", "verdict": "strip",
                  "redaction": {"aws-access-key": 1},
                  "findings": [{"scanner": "secrets", "rule_id": "secrets.aws",
                                "severity": "high", "owasp": "ASI03", "mitre": "T1552"}]})
    assert e["al"]["redaction"] == {"aws-access-key": 1}
    assert e["event"]["outcome"] == "success" and e["event"]["severity"] == "high"
    assert e["threat"]["technique"]["id"] == ["T1552"]


def test_export_writes_ndjson():
    buf = io.StringIO()
    assert export([BLOCK, BLOCK], buf) == 2
    lines = buf.getvalue().strip().splitlines()
    assert len(lines) == 2 and json.loads(lines[0])["event"]["kind"] == "alert"


def test_cli_export_from_real_ledger(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("mode: balanced\n", encoding="utf-8")
    rt = Runtime(cfg, data_dir=tmp_path / "data")
    rt.action_gate.authorize("spiffe://acme/agent/x", "exec_shell", {"cmd": "rm"})
    rt.close()

    out = tmp_path / "events.ndjson"
    r = runner.invoke(app, ["export", "--ledger", str(tmp_path / "data" / "ledger.jsonl"),
                            "--verdict", "block", "-o", str(out)])
    assert r.exit_code == 0, r.output
    events = [json.loads(line) for line in out.read_text().splitlines()]
    assert events and all(e["event"]["kind"] == "alert" for e in events)
    assert all(e["al"]["sig"] for e in events)  # every alert is verifiable
