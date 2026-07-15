"""Evidence pool — the dashboard reads the DATA plane's ledger, read-only.

The compose topology gives each plane its own ledger (one writer per chain),
which used to mean the dashboard (control plane) showed only its own boot
receipt while all the interesting gateway decisions sat unseen in al-core's
volume. These tests prove the fix: a read-only attach of the data plane's
mirror, merged plane-tagged reads, per-plane chain verification, and the new
``session`` / ``latency_ms`` receipt fields that give an alert its full
who/where context.
"""

from __future__ import annotations

import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from al_core.app import create_app
from al_core.audit.db import SqliteMirror
from al_core.audit.pool import EvidencePool, RemotePlane
from al_core.runtime import Runtime
from al_verify.verify import verify_chain, verify_receipt

TOKEN = "pool-admin-token"


def _runtime(tmp_path, name: str) -> Runtime:
    # Each plane signs with its OWN key under its own data dir (exactly the
    # compose layout: AL_KEYS__SIGNING_KEY_PATH=/app/data/keys/...).
    cfg = tmp_path / f"{name}.yaml"
    cfg.write_text("mode: balanced\n", encoding="utf-8")
    return Runtime(cfg, data_dir=tmp_path / name, admin_api_token=TOKEN,
                   keys={"signing_key_path":
                         str(tmp_path / name / "keys" / "mediator_ed25519")})


def _seed_dataplane(rt: Runtime) -> None:
    rt.record(actor="spiffe://acme/agent/claude-code", action="fetch",
              target="http://169.254.169.254/", verdict="block",
              block_reason="HOST_NOT_ALLOWED", latency_ms=12,
              findings=[{"scanner": "egress_policy", "rule_id": "policy.host_not_allowed",
                         "severity": "high", "owasp": "ASI02"}])
    rt.record(actor="spiffe://acme/agent/claude-code", action="mcp_tool_call",
              target="tool:exec_shell", verdict="block", block_reason="TOOL_DENIED",
              session="mcp:spiffe://acme/agent/claude-code",
              findings=[{"scanner": "tool_policy", "rule_id": "policy.explicit_deny",
                         "severity": "high", "owasp": "ASI02"}])
    rt.record(actor="spiffe://acme/user/tester", action="llm_call",
              target="anthropic:m", verdict="allow", latency_ms=340)


# -- read-only mirror ------------------------------------------------------------


def test_read_only_mirror_reads_a_live_db_and_cannot_write(tmp_path):
    rt = _runtime(tmp_path, "data")
    _seed_dataplane(rt)

    ro = SqliteMirror(tmp_path / "data" / "al.sqlite", read_only=True)
    assert ro.count_events() == rt.ledger.db.count_events()
    with pytest.raises(sqlite3.OperationalError):
        ro.upsert_event(rt.ledger.db.recent(1)[0])

    # Live: a write by the owner is visible to the open read-only connection.
    before = ro.count_events()
    rt.record(actor="user:x", action="fetch", target="t", verdict="allow")
    assert ro.count_events() == before + 1
    ro.close()
    rt.close()


def test_read_only_mirror_missing_file_raises(tmp_path):
    with pytest.raises(sqlite3.Error):
        SqliteMirror(tmp_path / "absent" / "al.sqlite", read_only=True)


def test_remote_plane_degrades_to_empty_when_absent(tmp_path):
    plane = RemotePlane("data", tmp_path / "nowhere")
    assert plane.query("count_events") is None
    assert plane.chain_status() == {"verified": True, "length": 0,
                                    "reason": None, "error": None}


# -- receipt fields: session + latency_ms ----------------------------------------


def test_session_and_latency_fields_sign_and_verify(tmp_path):
    rt = _runtime(tmp_path, "data")
    r = rt.record(actor="user:t", action="mcp_tool_call", target="tool:x",
                  verdict="block", block_reason="TOOL_DENIED",
                  session="sess-1", latency_ms=7)
    assert r["session"] == "sess-1" and r["latency_ms"] == 7
    verify_receipt(r, rt.public_key)  # the new fields are inside the signature
    # Absent fields stay absent (canonicalization: no nulls in receipts).
    r2 = rt.record(actor="user:t", action="fetch", target="t", verdict="allow")
    assert "session" not in r2 and "latency_ms" not in r2
    assert verify_chain(rt.ledger._jsonl.read_all(), rt.public_key) >= 2
    rt.close()


# -- merged pool ------------------------------------------------------------------


@pytest.fixture
def two_planes(tmp_path):
    data_rt = _runtime(tmp_path, "data")
    _seed_dataplane(data_rt)
    control_rt = _runtime(tmp_path, "control")
    control_rt.killswitch.engage("api", actor="user:op", reason="drill")
    control_rt.killswitch.disengage(actor="user:op")
    yield data_rt, control_rt
    data_rt.close()
    control_rt.close()


def _pool(tmp_path, control_rt) -> EvidencePool:
    return EvidencePool("control", control_rt.ledger.db,
                        [RemotePlane("data", tmp_path / "data")])


def test_pool_merges_and_tags_both_planes(tmp_path, two_planes):
    data_rt, control_rt = two_planes
    pool = _pool(tmp_path, control_rt)

    merged = pool.recent_filtered(limit=50)
    planes = {r["plane"] for r in merged}
    assert planes == {"data", "control"}
    # Newest first across BOTH chains.
    ts_list = [r["ts"] for r in merged]
    assert ts_list == sorted(ts_list, reverse=True)

    stats = pool.stats()
    assert stats["events"] == (data_rt.ledger.db.count_events()
                               + control_rt.ledger.db.count_events())
    assert stats["planes"]["data"] > 0 and stats["planes"]["control"] > 0
    assert stats["block_reasons"].get("HOST_NOT_ALLOWED") == 1

    series = pool.time_series(buckets=6, span_hours=24)
    assert sum(b["total"] for b in series) == stats["events"]
    pool.close()


def test_pool_receipt_by_seq_and_per_plane_keys(tmp_path, two_planes):
    data_rt, control_rt = two_planes
    pool = _pool(tmp_path, control_rt)

    # Data-plane seq 2 = the seeded mcp_tool_call (seq 0 is config:boot).
    r = pool.receipt_by_seq(2, None, "data")
    assert r is not None and r["plane"] == "data" and r["action"] == "mcp_tool_call"
    assert r["session"] == "mcp:spiffe://acme/agent/claude-code"

    # Same seq on the control plane is a different receipt.
    c = pool.receipt_by_seq(1, None, "control")
    assert c is not None and c["plane"] == "control" and c["action"] == "killswitch"

    # Each plane verifies against its OWN key — a cross-key verify must fail.
    body = {k: v for k, v in r.items() if k != "plane"}
    verify_receipt(body, pool.public_key_for("data", control_rt.public_key))
    with pytest.raises(Exception):
        verify_receipt(body, pool.public_key_for("control", control_rt.public_key))
    pool.close()


def test_pool_org_scoping_still_narrows(tmp_path, two_planes):
    data_rt, control_rt = two_planes
    pool = _pool(tmp_path, control_rt)
    acme = pool.recent_filtered(limit=50, org="acme")
    assert acme and all(r["actor"].startswith("spiffe://acme/") for r in acme)
    assert pool.recent_filtered(limit=50, org="ghost") == []
    pool.close()


def test_pool_chain_status_per_plane(tmp_path, two_planes):
    data_rt, control_rt = two_planes
    pool = _pool(tmp_path, control_rt)
    chains = pool.chains({"verified": True, "length": 3, "error": None})
    assert chains["control"]["verified"] is True
    assert chains["data"]["verified"] is True
    assert chains["data"]["reason"] is None
    assert chains["data"]["length"] == data_rt.ledger.db.count_events()
    pool.close()


def test_unreadable_pubkey_is_unavailable_not_a_broken_chain(tmp_path, two_planes):
    """A pubkey we cannot read means we could not CHECK the chain — it does not
    mean the chain is broken. Only a failed check ("invalid") is the tamper
    alarm; conflating the two makes that alarm cry wolf on a config typo (which
    is exactly what a native install does: it keeps keys/ beside the repo, not
    under the data dir)."""
    _, control_rt = two_planes
    plane = RemotePlane("data", tmp_path / "data",
                        pubkey_path=tmp_path / "nowhere" / "mediator_ed25519.pub")
    status = plane.chain_status()
    assert status["verified"] is False        # still fail-closed
    assert status["reason"] == "unavailable"  # ...but NOT reported as tampering
    assert "no usable public key" in status["error"]


def test_tampered_chain_is_invalid(tmp_path, two_planes):
    """The real alarm still fires: edit a signed receipt and the chain is
    reported invalid, not merely unavailable."""
    _, control_rt = two_planes
    jsonl = tmp_path / "data" / "ledger.jsonl"
    lines = jsonl.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[-1])
    assert tampered["verdict"] == "allow"  # the seeded llm_call
    tampered["verdict"] = "block"          # rewrite history: flip the verdict
    lines[-1] = json.dumps(tampered, separators=(",", ":"), sort_keys=True)
    jsonl.write_text("\n".join(lines) + "\n", encoding="utf-8")

    status = RemotePlane("data", tmp_path / "data").chain_status()
    assert status["verified"] is False
    assert status["reason"] == "invalid"


# -- the app: dashboard shows data-plane receipts ---------------------------------


def _auth():
    return {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def app_client(tmp_path):
    data_rt = _runtime(tmp_path, "data")
    _seed_dataplane(data_rt)
    data_rt.close()

    cfg = tmp_path / "control.yaml"
    cfg.write_text("mode: balanced\n", encoding="utf-8")
    application = create_app(
        cfg, data_dir=tmp_path / "control", admin_api_token=TOKEN,
        control={"dataplane_dir": str(tmp_path / "data")},
        keys={"signing_key_path":
              str(tmp_path / "control" / "keys" / "mediator_ed25519")},
    )
    with TestClient(application) as c:
        yield c


def test_api_receipts_include_data_plane(app_client):
    r = app_client.get("/api/receipts?limit=50", headers=_auth()).json()
    planes = {x["plane"] for x in r["receipts"]}
    assert "data" in planes and "control" in planes
    blocked = [x for x in r["receipts"] if x["verdict"] == "block"]
    assert any(x["block_reason"] == "HOST_NOT_ALLOWED" for x in blocked)


def test_api_summary_and_chain_cover_both_planes(app_client):
    s = app_client.get("/api/summary", headers=_auth()).json()
    assert s["planes"]["data"] > 0 and s["planes"]["control"] > 0
    assert set(s["chains"]) == {"control", "data"}
    assert s["chains"]["data"]["verified"] is True
    assert "killswitch" in s
    c = app_client.get("/api/chain", headers=_auth()).json()
    assert c["chains"]["data"]["verified"] is True


def test_api_receipt_detail_and_verify_per_plane(app_client):
    r = app_client.get("/api/receipts/2?plane=data", headers=_auth()).json()
    assert r["action"] == "mcp_tool_call" and r["plane"] == "data"
    assert r["session"] == "mcp:spiffe://acme/agent/claude-code"

    v = app_client.get("/api/verify/2?plane=data", headers=_auth()).json()
    assert v["verified"] is True and v["plane"] == "data"

    v2 = app_client.get("/api/verify/0?plane=control", headers=_auth()).json()
    assert v2["verified"] is True and v2["plane"] == "control"

    assert app_client.get("/api/receipts/1?plane=bogus",
                          headers=_auth()).status_code == 404


def test_api_search_reaches_data_plane(app_client):
    r = app_client.get("/api/search?q=exec_shell", headers=_auth()).json()
    assert r["count"] == 1 and r["receipts"][0]["plane"] == "data"


def test_api_still_401_without_token(app_client):
    assert app_client.get("/api/receipts").status_code == 401
    assert app_client.get("/api/receipts/1?plane=data").status_code == 401
