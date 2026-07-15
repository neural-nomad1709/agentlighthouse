"""tool_policy_test (Phase 3) — identity-bound default-deny + arg constraints.

Acceptance: out-of-policy tool denied pre-execution
with ASI02/ASI03 findings + block_reason; argument constraints enforced
(read_file outside /workspace denied; http_fetch to non-allow-host denied);
explicit deny wins; unknown identity denied.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from al_core.capability import ToolCall, ToolPolicy
from al_core.gateway.decision import BlockReason

POLICY = {
    "agents": {
        "spiffe://acme/agent/bot": {
            "allow": [
                {"tool": "http_fetch", "args": {"url": {"allow_hosts": ["docs.python.org", "*.internal"]}}},
                {"tool": "read_file", "args": {"path": {"allow_prefixes": ["/workspace/"],
                                                        "deny_prefixes": ["/etc/", "/workspace/.git/"]}}},
                {"tool": "set_mode", "args": {"mode": {"allow_values": ["fast", "safe"]}}},
            ],
            "deny": [{"tool": "exec_shell"}],
            "budgets": {"max_tool_calls_per_min": 60},
        },
        "default": {"allow": []},
    }
}

BOT = "spiffe://acme/agent/bot"


@pytest.fixture
def policy() -> ToolPolicy:
    return ToolPolicy.from_dict(POLICY)


def call(tool: str, actor: str = BOT, **args) -> ToolCall:
    return ToolCall(actor=actor, tool=tool, args=args)


# -- allow paths ----------------------------------------------------------------

def test_allowed_tool_with_valid_host(policy):
    d = policy.check(call("http_fetch", url="https://docs.python.org/3/library"))
    assert d.allowed


def test_allowed_wildcard_host(policy):
    assert policy.check(call("http_fetch", url="https://api.internal/x")).allowed


def test_allowed_read_within_workspace(policy):
    assert policy.check(call("read_file", path="/workspace/src/main.py")).allowed


def test_allowed_value_constraint(policy):
    assert policy.check(call("set_mode", mode="fast")).allowed


# -- default-deny ---------------------------------------------------------------

def test_unlisted_tool_denied(policy):
    d = policy.check(call("send_email", to="x@y.com"))
    assert not d.allowed and d.block_reason == BlockReason.TOOL_NOT_ALLOWED
    assert d.findings[0]["owasp"] == "ASI03"


def test_unknown_identity_denied(policy):
    d = policy.check(call("http_fetch", actor="spiffe://acme/agent/ghost",
                          url="https://docs.python.org/"))
    # falls through to `default` (allow: []) -> default-deny
    assert not d.allowed and d.block_reason == BlockReason.TOOL_NOT_ALLOWED


def test_no_default_policy_denies():
    p = ToolPolicy.from_dict({"agents": {BOT: {"allow": []}}})
    d = p.check(call("http_fetch", actor="spiffe://other/agent/x", url="https://a/"))
    assert not d.allowed and d.findings[0]["rule_id"] == "policy.no_identity_policy"


# -- explicit deny wins ---------------------------------------------------------

def test_explicit_deny_blocks(policy):
    d = policy.check(call("exec_shell", cmd="rm -rf /"))
    assert not d.allowed and d.block_reason == BlockReason.TOOL_DENIED
    assert d.findings[0]["owasp"] == "ASI02"


# -- argument constraints -------------------------------------------------------

def test_host_not_allowed_denied(policy):
    d = policy.check(call("http_fetch", url="https://evil.com/x"))
    assert d.block_reason == BlockReason.ARG_NOT_ALLOWED
    assert "host_not_allowed" in d.findings[0]["rule_id"]


def test_read_outside_workspace_denied(policy):
    d = policy.check(call("read_file", path="/etc/passwd"))
    assert d.block_reason == BlockReason.ARG_NOT_ALLOWED
    assert "prefix" in d.findings[0]["rule_id"]


def test_path_traversal_escape_denied(policy):
    # /workspace/../etc/passwd normalizes to /etc/passwd -> outside allow prefix
    d = policy.check(call("read_file", path="/workspace/../etc/passwd"))
    assert d.block_reason == BlockReason.ARG_NOT_ALLOWED


def test_deny_prefix_within_allow_denied(policy):
    # inside /workspace but under the denied .git subtree
    d = policy.check(call("read_file", path="/workspace/.git/config"))
    assert d.block_reason == BlockReason.ARG_NOT_ALLOWED
    assert "prefix_denied" in d.findings[0]["rule_id"]


def test_value_not_allowed_denied(policy):
    d = policy.check(call("set_mode", mode="dangerous"))
    assert d.block_reason == BlockReason.ARG_NOT_ALLOWED
    assert "value_not_allowed" in d.findings[0]["rule_id"]


def test_missing_constrained_arg_denied(policy):
    # allow rule constrains `path`; a call without it does not get the allow
    d = policy.check(call("read_file"))
    assert not d.allowed
    assert d.findings[0]["rule_id"].endswith("path.missing") or \
        d.block_reason == BlockReason.ARG_NOT_ALLOWED


# -- loading from YAML ----------------------------------------------------------

def test_loads_shipped_default_policy():
    root = Path(__file__).resolve().parents[1]
    p = ToolPolicy.from_yaml(root / "policies" / "default-deny.yaml")
    # the shipped policy allows claude-code read within /workspace
    d = p.check(ToolCall(actor="spiffe://acme/agent/claude-code", tool="read_file",
                         args={"path": "/workspace/app.py"}))
    assert d.allowed
    # and denies exec_shell
    d2 = p.check(ToolCall(actor="spiffe://acme/agent/claude-code", tool="exec_shell",
                          args={"cmd": "ls"}))
    assert d2.block_reason == BlockReason.TOOL_DENIED


def test_unknown_policy_key_rejected():
    with pytest.raises(Exception):
        ToolPolicy.from_dict({"agents": {BOT: {"allau": []}}})  # typo'd key
