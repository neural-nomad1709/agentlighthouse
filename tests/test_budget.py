"""Per-actor tool-call budgets — the rate tripwire, actually enforced.

`AgentPolicy.budgets.max_tool_calls_per_min` was schema-accepted but never
checked: a security field that promised a rate limit it did not perform. This
enforces it at the ActionGate choke point with a per-actor sliding 60s window.
A budget denial is a first-class `BUDGET_EXCEEDED` decision, receipted like any
other. An actor with no budget configured is unaffected.
"""

from __future__ import annotations

import pytest

from al_core.capability.gate import ActionGate
from al_core.capability.policy import ToolPolicy
from al_core.gateway.decision import BlockReason

ACTOR = "spiffe://acme/agent/bot"

POLICY = {
    "agents": {
        ACTOR: {
            "allow": [{"tool": "read_file"}],
            "budgets": {"max_tool_calls_per_min": 3},
        },
        "spiffe://acme/agent/unlimited": {
            "allow": [{"tool": "read_file"}],
        },
        "default": {"allow": []},
    }
}


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def make_gate(clock: FakeClock) -> ActionGate:
    return ActionGate(ToolPolicy.from_dict(POLICY), clock=clock)


def allowed(gate: ActionGate, actor: str = ACTOR) -> bool:
    return gate.authorize(actor, "read_file", {}).allowed


class TestBudgetEnforcement:
    def test_calls_within_the_budget_pass(self) -> None:
        gate = make_gate(FakeClock())
        assert [allowed(gate) for _ in range(3)] == [True, True, True]

    def test_the_call_over_budget_is_denied_with_a_budget_reason(self) -> None:
        gate = make_gate(FakeClock())
        for _ in range(3):
            assert allowed(gate)
        outcome = gate.authorize(ACTOR, "read_file", {})
        assert not outcome.allowed
        assert outcome.decision.block_reason == BlockReason.BUDGET_EXCEEDED

    def test_a_budget_denial_is_receipted(self) -> None:
        recorded: list[dict] = []
        gate = ActionGate(ToolPolicy.from_dict(POLICY), clock=FakeClock(),
                          recorder=lambda **f: recorded.append(f))
        for _ in range(4):
            gate.authorize(ACTOR, "read_file", {})
        budget_receipts = [r for r in recorded
                           if r.get("block_reason") == BlockReason.BUDGET_EXCEEDED]
        assert len(budget_receipts) == 1
        assert budget_receipts[0]["actor"] == ACTOR
        assert budget_receipts[0]["verdict"] == "block"

    def test_the_window_slides_calls_pass_again_after_60s(self) -> None:
        clock = FakeClock()
        gate = make_gate(clock)
        for _ in range(3):
            assert allowed(gate)
        assert not allowed(gate)          # over budget now
        clock.advance(61)                  # the earliest calls age out
        assert allowed(gate)               # room again

    def test_the_window_is_a_true_slide_not_a_fixed_bucket(self) -> None:
        clock = FakeClock()
        gate = make_gate(clock)
        assert allowed(gate)               # t=1000
        clock.advance(30)
        assert allowed(gate) and allowed(gate)  # t=1030: three in the window
        assert not allowed(gate)           # 4th within 60s: denied
        clock.advance(31)                  # t=1061: the t=1000 call drops out
        assert allowed(gate)               # one slot freed

    def test_an_actor_with_no_budget_is_unaffected(self) -> None:
        gate = make_gate(FakeClock())
        assert all(allowed(gate, "spiffe://acme/agent/unlimited") for _ in range(50))

    def test_budgets_are_per_actor(self) -> None:
        gate = make_gate(FakeClock())
        for _ in range(3):
            assert allowed(gate)
        assert not allowed(gate)           # bot is spent
        # a different budgeted-but-fresh actor is independent
        assert allowed(gate, "spiffe://acme/agent/unlimited")

    def test_a_policy_denied_call_does_not_consume_budget(self) -> None:
        gate = make_gate(FakeClock())
        for _ in range(5):
            # 'delete_file' has no allow rule: denied by policy, never runs
            assert not gate.authorize(ACTOR, "delete_file", {}).allowed
        # the budget is untouched — three real calls still pass
        assert [allowed(gate) for _ in range(3)] == [True, True, True]


def test_the_policy_exposes_a_budget_lookup() -> None:
    policy = ToolPolicy.from_dict(POLICY)
    assert policy.budget_for(ACTOR) == 3
    assert policy.budget_for("spiffe://acme/agent/unlimited") is None
    assert policy.budget_for("spiffe://acme/agent/stranger") is None  # default, no budget
