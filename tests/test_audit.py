"""Audit ledger: JSONL canonical + SQLite mirror + verify-on-startup."""

from __future__ import annotations

import pytest

from al_verify.verify import VerificationError

from al_core.audit import Ledger, verify_ledger_file


def _make(tmp_path, signing_key, public_key):
    return Ledger(
        signing_key,
        public_key,
        jsonl_path=tmp_path / "ledger.jsonl",
        db_path=tmp_path / "al.sqlite",
    )


def test_record_appends_and_verifies(tmp_path, signing_key, public_key):
    ledger = _make(tmp_path, signing_key, public_key)
    ledger.record(actor="spiffe://acme/agent/x", action="fetch",
                  target="https://e.com", verdict="allow")
    ledger.record(actor="spiffe://acme/agent/x", action="mcp_tool_call",
                  target="tool:send", verdict="block", block_reason="TOOL_NOT_ALLOWED")
    assert ledger.verify(public_key) == 2
    ledger.close()

    # Standalone file verify agrees.
    assert verify_ledger_file(tmp_path / "ledger.jsonl", public_key) == 2


def test_mirror_reflects_events(tmp_path, signing_key, public_key):
    ledger = _make(tmp_path, signing_key, public_key)
    ledger.record(actor="spiffe://acme/agent/x", action="fetch",
                  target="https://e.com", verdict="allow")
    assert ledger.db.count_events() == 1
    recent = ledger.db.recent()
    assert recent[0]["action"] == "fetch"
    ledger.close()


def test_resume_continues_chain(tmp_path, signing_key, public_key):
    ledger = _make(tmp_path, signing_key, public_key)
    ledger.record(actor="spiffe://acme/agent/x", action="fetch",
                  target="https://e.com", verdict="allow")
    ledger.close()

    # Reopen over the same files: seq resumes, chain still verifies.
    ledger2 = _make(tmp_path, signing_key, public_key)
    assert ledger2.next_seq == 1
    ledger2.record(actor="spiffe://acme/agent/x", action="fetch",
                   target="https://f.com", verdict="allow")
    assert ledger2.verify(public_key) == 2
    ledger2.close()


def test_tampered_jsonl_refuses_on_startup(tmp_path, signing_key, public_key):
    ledger = _make(tmp_path, signing_key, public_key)
    ledger.record(actor="spiffe://acme/agent/x", action="mcp_tool_call",
                  target="tool:send", verdict="block", block_reason="TOOL_NOT_ALLOWED")
    ledger.close()

    path = tmp_path / "ledger.jsonl"
    path.write_text(path.read_text().replace('"block"', '"allow"'), encoding="utf-8")

    with pytest.raises(VerificationError):
        _make(tmp_path, signing_key, public_key)
