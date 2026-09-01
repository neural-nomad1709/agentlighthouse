"""HITL + taint persistence — a restart must not change any decision.

The invariants under test: a pending approval survives a restart with its
original deadline (persistence never extends one, even across wall-clock
steps); a tainted session stays tainted (taint is monotonic within a session);
resolutions and lapses never rehydrate (fail-closed — receipts, not the state
store, record what was decided); and both gates behave identically with no
store attached.
"""

from __future__ import annotations

import time

import pytest

from al_core.capability.hitl import HitlGate
from al_core.capability.store import CapabilityStore
from al_core.capability.taint import TaintSource, TaintTracker


@pytest.fixture
def store_path(tmp_path):
    return tmp_path / "capability_state.db"


def reopened(store_path) -> CapabilityStore:
    """A fresh store handle on the same file — the 'after restart' view."""
    return CapabilityStore(store_path)


# -- pending approvals survive a restart -------------------------------------------

def test_pending_request_survives_restart_with_identity_intact(store_path):
    gate = HitlGate(timeout_s=100.0, store=CapabilityStore(store_path))
    req = gate.submit("spiffe://acme/agent/claude-code", "send_email")

    gate2 = HitlGate(timeout_s=100.0, store=reopened(store_path))
    assert gate2.status(req.request_id) == "pending"
    rehydrated = {r.request_id: r for r in gate2.pending()}[req.request_id]
    assert rehydrated.actor == "spiffe://acme/agent/claude-code"
    assert rehydrated.tool == "send_email"
    # resolvable in the new process, resolver recorded
    assert gate2.approve(req.request_id, by="user:alice")
    assert gate2.status(req.request_id) == "approved"


def test_restart_never_extends_a_deadline(store_path):
    gate = HitlGate(timeout_s=2.0, store=CapabilityStore(store_path))
    req = gate.submit("a", "send_email")
    time.sleep(0.5)  # burn part of the deadline before the "restart"

    gate2 = HitlGate(timeout_s=2.0, store=reopened(store_path))
    remaining = gate2.remaining_s(req.request_id)
    assert remaining is not None and remaining <= 1.55, (
        f"deadline was extended across restart: {remaining}s left of 2.0s "
        f"after 0.5s had already elapsed"
    )
    time.sleep(remaining + 0.1)  # past the ORIGINAL deadline
    assert gate2.status(req.request_id) == "timed_out"
    assert not gate2.approve(req.request_id)  # timeout remains a denial


def test_lapsed_request_stays_a_denial_after_restart(store_path):
    gate = HitlGate(timeout_s=0.05, store=CapabilityStore(store_path))
    req = gate.submit("a", "send_email")
    time.sleep(0.08)

    gate2 = HitlGate(timeout_s=0.05, store=reopened(store_path))
    assert not gate2.approve(req.request_id)
    assert not gate2.decision(req.request_id).allowed
    assert gate2.pending() == []


def test_a_resolution_does_not_survive_a_restart(store_path):
    """Only PENDING requests rehydrate. An approval that was never consumed
    dies with the process — fail-closed, and it stops an approved request_id
    from becoming a never-expiring allow-token across restarts. Receipts, not
    the state store, are the record of what was resolved."""
    gate = HitlGate(timeout_s=100.0, store=CapabilityStore(store_path))
    approved = gate.submit("a", "send_email")
    denied = gate.submit("a", "delete_backups")
    gate.approve(approved.request_id, by="user:alice")
    gate.deny(denied.request_id, by="user:alice")

    gate2 = HitlGate(timeout_s=100.0, store=reopened(store_path))
    for req in (approved, denied):
        assert gate2.status(req.request_id) == "unknown"
        assert not gate2.decision(req.request_id).allowed
        assert not gate2.approve(req.request_id)


def test_the_store_prunes_what_will_never_rehydrate(store_path):
    """Resolved rows are deleted on resolution and lapsed rows on the next
    boot, so the table holds only live pending requests — a busy mediator must
    not materialize its whole approval history on every start."""
    store = CapabilityStore(store_path)
    gate = HitlGate(timeout_s=0.05, store=store)
    resolved = gate.submit("a", "send_email")
    gate.deny(resolved.request_id, by="user:alice")
    gate.submit("a", "send_email")  # will lapse
    time.sleep(0.08)

    assert len(store.load_approvals()) <= 1  # the lapsed row, at most
    HitlGate(timeout_s=0.05, store=reopened(store_path))  # boot prunes lapsed
    assert reopened(store_path).load_approvals() == []


def test_a_backward_clock_step_fails_closed_not_open(store_path):
    """Wall time can step backward (NTP correction, VM snapshot restore). A
    submission that appears to come from the future is treated as lapsed —
    never as a fresh deadline."""
    store = CapabilityStore(store_path)
    gate = HitlGate(timeout_s=300.0, store=store)
    req = gate.submit("a", "send_email")
    # simulate the clock stepping backward past the submission moment
    with store._lock, store._conn:
        store._conn.execute(
            "UPDATE approvals SET created_at_wall = created_at_wall + 3600 "
            "WHERE request_id = ?", (req.request_id,))

    gate2 = HitlGate(timeout_s=300.0, store=reopened(store_path))
    assert not gate2.approve(req.request_id)
    assert not gate2.decision(req.request_id).allowed


# -- taint survives a restart (closes a fail-open) ---------------------------------

def test_tainted_session_stays_tainted_across_restart(store_path):
    tracker = TaintTracker(store=CapabilityStore(store_path))
    tracker.mark("sess-1", TaintSource.INJECTION_DETECTED)
    assert tracker.is_tainted("sess-1")

    tracker2 = TaintTracker(store=reopened(store_path))
    assert tracker2.is_tainted("sess-1"), "restart cleared taint — fail-open"
    assert tracker2.sources("sess-1") == [TaintSource.INJECTION_DETECTED]


def test_taint_sources_accumulate_and_persist(store_path):
    tracker = TaintTracker(store=CapabilityStore(store_path))
    tracker.mark("sess-1", TaintSource.WEB_FETCH)
    tracker.mark("sess-1", TaintSource.INJECTION_DETECTED)
    tracker.mark("sess-1", TaintSource.WEB_FETCH)  # idempotent per source

    tracker2 = TaintTracker(store=reopened(store_path))
    assert tracker2.sources("sess-1") == [
        TaintSource.WEB_FETCH, TaintSource.INJECTION_DETECTED
    ]


def test_explicit_clear_also_clears_the_store(store_path):
    tracker = TaintTracker(store=CapabilityStore(store_path))
    tracker.mark("sess-1", TaintSource.WEB_FETCH)
    tracker.clear("sess-1")

    tracker2 = TaintTracker(store=reopened(store_path))
    assert not tracker2.is_tainted("sess-1")


# -- the Runtime wires the store in -------------------------------------------------

def test_runtime_restart_preserves_pending_approvals_and_taint(tmp_path):
    from al_core.runtime import Runtime

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("mode: balanced\n", encoding="utf-8")

    rt = Runtime(cfg, data_dir=tmp_path / "data", admin_api_token="t")
    gate = rt.action_gate
    req = gate.hitl.submit("spiffe://acme/agent/claude-code", "send_email")
    gate.taint.mark("sess-1", TaintSource.INJECTION_DETECTED)
    rt.close()

    rt2 = Runtime(cfg, data_dir=tmp_path / "data", admin_api_token="t")
    try:
        gate2 = rt2.action_gate
        assert gate2.hitl.status(req.request_id) == "pending"
        assert gate2.taint.is_tainted("sess-1")
    finally:
        rt2.close()


# -- storeless behaviour is unchanged ----------------------------------------------

def test_gates_without_a_store_remain_memory_only(tmp_path):
    gate = HitlGate(timeout_s=100.0)
    req = gate.submit("a", "send_email")
    assert gate.status(req.request_id) == "pending"
    tracker = TaintTracker()
    tracker.mark("s", TaintSource.WEB_FETCH)
    assert tracker.is_tainted("s")
