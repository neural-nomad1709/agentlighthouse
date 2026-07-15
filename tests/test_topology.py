"""Phase 5 — the compose topology IS the segregation boundary.

The live proof runs on `docker compose up` (the one-shot probe services must
exit 0 before any agent starts). These tests guard the *invariants of the
topology file* so a future edit cannot silently delete the boundary — they run
everywhere, including Windows, where Docker may not be present.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

COMPOSE = Path(__file__).resolve().parents[1] / "docker-compose.yml"


@pytest.fixture(scope="module")
def compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def test_agent_net_is_internal(compose):
    assert compose["networks"]["agent-net"]["internal"] is True


def test_agents_attach_only_to_agent_net(compose):
    for name in ("agent-sandbox", "agent-selftest", "agent-control-probe"):
        assert compose["services"][name]["networks"] == ["agent-net"], name


def test_control_plane_is_unreachable_from_agents(compose):
    """al-control lives on control-net only — agent-net has no path to it."""
    control = compose["services"]["al-control"]
    assert control["networks"] == ["control-net"]
    assert "agent-net" not in control["networks"]
    # Its published port is bound to host loopback, not to a shared network.
    assert all(p.startswith("127.0.0.1:") for p in control["ports"])


def test_segregation_probe_gates_the_agent_workload(compose):
    """No agent starts until 'no route to the control plane' is proven live."""
    probe = compose["services"]["agent-control-probe"]
    cmd = probe["command"]
    assert cmd[:2] == ["egress", "selftest"]
    assert "al-control:8888" in cmd  # the admin API + kill switch
    assert len([c for c in cmd if c.startswith("al-control:")]) >= 2
    deps = compose["services"]["agent-sandbox"]["depends_on"]
    assert deps["agent-control-probe"]["condition"] == "service_completed_successfully"
    assert deps["agent-selftest"]["condition"] == "service_completed_successfully"


def test_killswitch_crosses_the_boundary_as_a_file_not_a_route(compose):
    """The only control->data crossing is the sentinel volume."""
    core, control = compose["services"]["al-core"], compose["services"]["al-control"]
    assert "al-killswitch:/app/killswitch" in core["volumes"]
    assert "al-killswitch:/app/killswitch" in control["volumes"]
    assert core["environment"]["AL_CONTROL__KILLSWITCH_DIR"] == "/app/killswitch"
    assert control["environment"]["AL_CONTROL__KILLSWITCH_DIR"] == "/app/killswitch"
    # Separate ledgers: each plane's evidence chain has exactly one writer.
    assert "al-data:/app/data" in core["volumes"]
    assert "al-control-data:/app/data" in control["volumes"]
    # The dashboard reads the data plane's evidence over a shared volume,
    # opened read-only in code (SQLite mode=ro) — al-core stays the single
    # writer of that chain. Without this mount the dashboard shows only the
    # control plane's own receipts, i.e. nothing an operator cares about.
    assert "al-data:/app/dataplane" in control["volumes"]
    assert control["environment"]["AL_CONTROL__DATAPLANE_DIR"] == "/app/dataplane"


def test_hardened_runtime_baseline_applies_to_every_service(compose):
    for name, svc in compose["services"].items():
        # The anchor merges these in; probes set them explicitly.
        assert svc.get("cap_drop") == ["ALL"], name
        assert svc.get("security_opt") == ["no-new-privileges:true"], name
        assert svc.get("read_only") is True, name
