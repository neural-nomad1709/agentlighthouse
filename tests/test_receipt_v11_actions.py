"""Receipt spec v1.1 (AL-0.5, decision D2): additive action vocabulary.

The remote-execution plane (access_control) records actions no proxy ever
emits: opening and closing an authenticated session, running a catalogued
operation, requesting permission for a gated one. D2 resolved to extend the
closed vocabulary additively — `remote_exec`, `session_open`, `session_close`,
`permission_request` — rather than launder them through `mcp_tool_call` with
the truth in a detail field.

Backward compatibility is the acceptance: every pre-existing receipt still
verifies (verification is over canonical bytes + signature, so the vocabulary
never enters the crypto), and the v1.0 eleven remain valid.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from al_core.receipt import ACTIONS, ReceiptSigner
from al_verify.verify import verify_chain, verify_receipt

V10_ACTIONS = (
    "http_forward", "fetch", "llm_call", "mcp_tool_call", "mcp_tool_result",
    "memory_read", "memory_write", "skill_load", "a2a_message", "config_change",
    "killswitch",
)
V11_ACTIONS = ("remote_exec", "session_open", "session_close", "permission_request")


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


def test_vocabulary_is_a_strict_superset_of_v10():
    assert set(V10_ACTIONS) <= set(ACTIONS)
    assert set(V11_ACTIONS) <= set(ACTIONS)


@pytest.mark.parametrize("action", V11_ACTIONS)
def test_new_actions_produce_receipts_al_verify_accepts(key, action):
    signer = ReceiptSigner(key)
    receipt = signer.record(
        actor="spiffe://acme/agent/claude-code",
        action=action,
        target="host:win01",
        verdict="allow",
        session="SES-001",
    )
    verify_receipt(receipt, key.public_key())  # raises on failure


def test_a_mixed_chain_verifies_end_to_end(key):
    signer = ReceiptSigner(key)
    chain = [
        signer.record(actor="a", action="session_open", target="host:win01", verdict="allow"),
        signer.record(actor="a", action="permission_request", target="op:restart-iis",
                      verdict="ask"),
        signer.record(actor="a", action="remote_exec", target="op:restart-iis",
                      verdict="allow"),
        signer.record(actor="a", action="mcp_tool_call", target="tool:x", verdict="allow"),
        signer.record(actor="a", action="session_close", target="host:win01", verdict="allow"),
    ]
    verify_chain(chain, key.public_key())


def test_pre_existing_v10_receipts_still_verify(key):
    signer = ReceiptSigner(key)
    chain = [
        signer.record(actor="user:alice", action=a, target=f"t:{a}", verdict="allow")
        for a in V10_ACTIONS
    ]
    verify_chain(chain, key.public_key())


def test_schema_enum_matches_the_producer_vocabulary():
    schema = json.loads(
        (Path(__file__).parents[1] / "spec" / "receipt-v1.schema.json")
        .read_text(encoding="utf-8")
    )
    assert set(schema["properties"]["action"]["enum"]) == set(ACTIONS)


def test_an_unknown_action_is_still_refused_by_the_producer(key):
    signer = ReceiptSigner(key)
    with pytest.raises(Exception):
        signer.record(actor="a", action="made_up_action", target="t", verdict="allow")


def test_mcp_client_reply_receipt_verifies(key):
    """Added 2026-09-30, additively: the agent answering an MCP server request."""
    signer = ReceiptSigner(key)
    receipt = signer.record(actor="spiffe://acme/agent/claude-code",
                            action="mcp_client_reply",
                            target="mcp:sampling/createMessage:reply", verdict="strip",
                            redaction={"aws-access-key": 1})
    verify_receipt(receipt, key.public_key())
