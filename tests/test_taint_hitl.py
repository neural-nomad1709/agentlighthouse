"""taint_test + hitl_test (Phase 3).

taint: untrusted ingestion taints a session (monotonic, records sources).
hitl: irreversible verbs pause for approval; approve → allow; deny/timeout →
deny; a tainted session widens the gate to protected ops.
"""

from __future__ import annotations

from al_core.capability import HitlGate, TaintSource, TaintTracker
from al_core.gateway.decision import BlockReason


# -- taint ----------------------------------------------------------------------

def test_session_starts_untainted():
    t = TaintTracker()
    assert not t.is_tainted("s1")
    assert t.sources("s1") == []


def test_mark_taints_and_records_source():
    t = TaintTracker()
    t.mark("s1", TaintSource.WEB_FETCH)
    assert t.is_tainted("s1")
    assert TaintSource.WEB_FETCH in t.sources("s1")


def test_taint_is_monotonic_and_dedups_sources():
    t = TaintTracker()
    t.mark("s1", TaintSource.WEB_FETCH)
    t.mark("s1", TaintSource.WEB_FETCH)  # dup
    t.mark("s1", TaintSource.INJECTION_DETECTED)
    assert t.sources("s1") == [TaintSource.WEB_FETCH, TaintSource.INJECTION_DETECTED]
    assert t.is_tainted("s1")


def test_taint_is_per_session():
    t = TaintTracker()
    t.mark("s1", TaintSource.WEB_FETCH)
    assert not t.is_tainted("s2")


def test_clear_resets():
    t = TaintTracker()
    t.mark("s1", TaintSource.WEB_FETCH)
    t.clear("s1")
    assert not t.is_tainted("s1")


# -- hitl classification --------------------------------------------------------

def test_irreversible_verbs_detected():
    g = HitlGate()
    for tool in ("send_email", "delete_file", "transfer_funds", "publish_post",
                 "deploy_service", "wire_payment"):
        assert g.is_irreversible(tool), tool


def test_read_is_not_irreversible():
    g = HitlGate()
    assert not g.is_irreversible("read_file")
    assert not g.requires_approval("read_file")


def test_tainted_session_widens_gate_to_protected():
    g = HitlGate()
    # write_file is protected but not irreversible: gated only when tainted
    assert not g.requires_approval("write_file", tainted=False)
    assert g.requires_approval("write_file", tainted=True)
    # irreversible gates regardless of taint
    assert g.requires_approval("send_email", tainted=False)


def test_extra_irreversible_configurable():
    g = HitlGate(extra_irreversible=("custom_action",))
    assert g.is_irreversible("custom_action")


# -- hitl lifecycle -------------------------------------------------------------

def test_pending_request_blocks_hitl_required():
    g = HitlGate()
    req = g.submit("spiffe://a/agent/b", "send_email")
    d = g.decision(req.request_id)
    assert not d.allowed and d.block_reason == BlockReason.HITL_REQUIRED
    assert d.findings[0]["owasp"] == "ASI09"


def test_approval_allows():
    g = HitlGate()
    req = g.submit("a", "send_email")
    assert g.approve(req.request_id)
    assert g.decision(req.request_id).allowed


def test_denial_blocks():
    g = HitlGate()
    req = g.submit("a", "send_email")
    assert g.deny(req.request_id)
    d = g.decision(req.request_id)
    assert not d.allowed and d.block_reason == BlockReason.HITL_DENIED


def test_timeout_is_denial():
    clock = {"t": 1000.0}
    g = HitlGate(timeout_s=30, clock=lambda: clock["t"])
    req = g.submit("a", "send_email")
    assert g.status(req.request_id) == "pending"
    clock["t"] += 31  # lapse
    assert g.status(req.request_id) == "timed_out"
    d = g.decision(req.request_id)
    assert not d.allowed and d.block_reason == BlockReason.HITL_DENIED
    assert d.findings[0]["rule_id"] == "hitl.timed_out"


def test_cannot_approve_after_timeout():
    clock = {"t": 0.0}
    g = HitlGate(timeout_s=10, clock=lambda: clock["t"])
    req = g.submit("a", "send_email")
    clock["t"] = 20
    assert not g.approve(req.request_id)  # too late
    assert not g.decision(req.request_id).allowed


def test_double_resolve_rejected():
    g = HitlGate()
    req = g.submit("a", "send_email")
    assert g.approve(req.request_id)
    assert not g.deny(req.request_id)  # already resolved


def test_unknown_request_denies():
    g = HitlGate()
    assert not g.decision("hitl_nope").allowed


def test_pending_list():
    g = HitlGate()
    r1 = g.submit("a", "send_email")
    r2 = g.submit("a", "delete_file")
    g.approve(r1.request_id)
    pending_ids = [r.request_id for r in g.pending()]
    assert pending_ids == [r2.request_id]
