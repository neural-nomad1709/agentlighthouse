"""L4 identity-bound tool policy — the moat (ASI02/ASI03).

Every tool call is evaluated against a **default-deny** policy keyed on the
agent's SPIFFE identity: a tool runs only if this identity has an explicit
allow rule *and* the call's arguments satisfy that rule's constraints. No
identity, no matching allow, or a violated constraint → deny, pre-execution,
with an agent-legible ``block_reason``.

Policy is data (YAML), not code, so it hot-reloads and is auditable:

    agents:
      "spiffe://acme/agent/claude-code":
        allow:
          - tool: http_fetch
            args: { url: { allow_hosts: [docs.python.org, "*.internal"] } }
          - tool: read_file
            args: { path: { allow_prefixes: [/workspace/], deny_prefixes: [/etc/, /secrets/] } }
        deny:
          - { tool: exec_shell }
        budgets: { max_tool_calls_per_min: 60 }
      default: { allow: [] }          # unknown identities: deny everything

Precedence within an identity: an explicit ``deny`` rule always wins, then an
``allow`` rule whose constraints pass; otherwise default-deny. Constraints are
conjunctive (every listed arg constraint must hold).
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict

from ..gateway.decision import BlockReason, Decision, finding
from ..gateway.ssrf import host_allowed

_STRICT = ConfigDict(extra="forbid")


class ArgConstraint(BaseModel):
    """Constraints on one argument's value. All present checks must pass."""

    model_config = _STRICT
    allow_hosts: list[str] | None = None       # value is a URL/host; host must match
    allow_prefixes: list[str] | None = None     # normalized path must start with one
    deny_prefixes: list[str] | None = None      # normalized path must start with none
    allow_values: list[Any] | None = None       # value ∈ set
    deny_values: list[Any] | None = None        # value ∉ set
    max_len: int | None = None                  # str length cap


class ToolRule(BaseModel):
    model_config = _STRICT
    tool: str
    args: dict[str, ArgConstraint] = {}


class BudgetRule(BaseModel):
    model_config = _STRICT
    max_tool_calls_per_min: int | None = None


class AgentPolicy(BaseModel):
    model_config = _STRICT
    allow: list[ToolRule] = []
    deny: list[ToolRule] = []
    budgets: BudgetRule = BudgetRule()


class ToolPolicyConfig(BaseModel):
    model_config = _STRICT
    agents: dict[str, AgentPolicy] = {}


@dataclass(frozen=True)
class ToolCall:
    """One tool invocation to authorize. ``args`` maps arg name -> value."""

    actor: str
    tool: str
    args: dict[str, Any] = field(default_factory=dict)


def _normalize_path(value: Any) -> str:
    """Collapse ``..`` / ``.`` so a prefix check cannot be walked out of.

    ``/workspace/../etc/passwd`` normalizes to ``/etc/passwd`` and fails an
    ``allow_prefixes: [/workspace/]`` check — traversal cannot escape."""
    s = str(value).replace("\\", "/")
    normed = posixpath.normpath(s)
    # normpath strips a trailing slash; keep leading slash semantics intact.
    if s.startswith("/") and not normed.startswith("/"):
        normed = "/" + normed
    return normed


def _host_of(value: Any) -> str:
    s = str(value)
    parts = urlsplit(s if "://" in s else "//" + s)
    return (parts.hostname or "").lower()


def _constraint_fails(name: str, value: Any, c: ArgConstraint) -> str | None:
    """Return a rule_id describing the first failure, or None if the value passes."""
    if c.max_len is not None and len(str(value)) > c.max_len:
        return f"arg.{name}.too_long"
    if c.allow_hosts is not None:
        if not host_allowed(_host_of(value), c.allow_hosts):
            return f"arg.{name}.host_not_allowed"
    if c.allow_prefixes is not None:
        p = _normalize_path(value)
        if not any(p == pre.rstrip("/") or p.startswith(pre if pre.endswith("/") else pre + "/")
                   for pre in c.allow_prefixes):
            return f"arg.{name}.prefix_not_allowed"
    if c.deny_prefixes is not None:
        p = _normalize_path(value)
        if any(p == pre.rstrip("/") or p.startswith(pre if pre.endswith("/") else pre + "/")
               for pre in c.deny_prefixes):
            return f"arg.{name}.prefix_denied"
    if c.allow_values is not None and value not in c.allow_values:
        return f"arg.{name}.value_not_allowed"
    if c.deny_values is not None and value in c.deny_values:
        return f"arg.{name}.value_denied"
    return None


def _rule_matches_args(rule: ToolRule, call: ToolCall) -> str | None:
    """None if every constraint holds; else the failing rule_id.

    A constraint on an argument the call does not supply fails closed — an
    allow rule that constrains ``path`` exists precisely to bound ``path``, so
    a call omitting it does not get the allow (it falls through to deny)."""
    for arg_name, constraint in rule.args.items():
        if arg_name not in call.args:
            return f"arg.{arg_name}.missing"
        failure = _constraint_fails(arg_name, call.args[arg_name], constraint)
        if failure is not None:
            return failure
    return None


class ToolPolicy:
    """Evaluates tool calls against a :class:`ToolPolicyConfig` (default-deny)."""

    DEFAULT_KEY = "default"

    def __init__(self, config: ToolPolicyConfig) -> None:
        self._config = config

    @classmethod
    def from_yaml(cls, path: str | Path) -> "ToolPolicy":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls(ToolPolicyConfig(**raw))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolPolicy":
        return cls(ToolPolicyConfig(**data))

    def _policy_for(self, actor: str) -> AgentPolicy | None:
        return self._config.agents.get(actor) or self._config.agents.get(self.DEFAULT_KEY)

    def check(self, call: ToolCall) -> Decision:
        """Authorize one tool call. Allow only on an explicit, satisfied rule."""
        policy = self._policy_for(call.actor)
        if policy is None:
            return Decision.block(
                BlockReason.TOOL_NOT_ALLOWED,
                [finding("tool_policy", "policy.no_identity_policy", "high",
                         owasp="ASI03", mitre="T1078")],
            )

        # Explicit deny wins over everything.
        for rule in policy.deny:
            if rule.tool == call.tool and _rule_matches_args(rule, call) is None:
                return Decision.block(
                    BlockReason.TOOL_DENIED,
                    [finding("tool_policy", "policy.explicit_deny", "high",
                             owasp="ASI02", mitre="T1059")],
                )

        # An allow rule for this tool whose constraints all pass.
        arg_failure: str | None = None
        tool_seen = False
        for rule in policy.allow:
            if rule.tool != call.tool:
                continue
            tool_seen = True
            failure = _rule_matches_args(rule, call)
            if failure is None:
                return Decision.allow()
            arg_failure = failure

        if tool_seen and arg_failure is not None:
            # The tool is allowed in principle, but an argument constraint failed.
            return Decision.block(
                BlockReason.ARG_NOT_ALLOWED,
                [finding("tool_policy", f"policy.{arg_failure}", "high",
                         owasp="ASI02", mitre="T1059")],
            )

        return Decision.block(
            BlockReason.TOOL_NOT_ALLOWED,
            [finding("tool_policy", "policy.default_deny", "high",
                     owasp="ASI03", mitre="T1078")],
        )


__all__ = [
    "AgentPolicy",
    "ArgConstraint",
    "BudgetRule",
    "ToolCall",
    "ToolPolicy",
    "ToolPolicyConfig",
    "ToolRule",
]
