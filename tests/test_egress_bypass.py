"""L0 boot bypass self-test (egress_bypass_test — Phase 1 acceptance).

Failure-mode table row: "egress bypass succeeds at boot → refuse start."
Out-of-band connection failure = healthy; success = signed CRITICAL receipt
and the core refuses to start. Plus the portable nftables ruleset rendering.
"""

from __future__ import annotations

import json

import pytest

from al_core.config import EgressConfig
from al_core.egress import (
    EgressBypassError,
    parse_target,
    probe_bypass,
    render_ruleset,
    self_test_enabled,
)
from al_core.keys import generate_signing_key
from al_core.runtime import Runtime


class FakeSocket:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _connect_success(addr, timeout, source_address):
    return FakeSocket()


def _connect_refused(addr, timeout, source_address):
    raise OSError("no route to host")


# -- probe ---------------------------------------------------------------------

def test_probe_reports_reached_targets():
    reached = probe_bypass(["1.1.1.1:443", "8.8.8.8:53"], connect=_connect_success)
    assert reached == ["1.1.1.1:443", "8.8.8.8:53"]


def test_probe_all_refused_is_healthy():
    assert probe_bypass(["1.1.1.1:443"], connect=_connect_refused) == []


def test_probe_mixed_results():
    def connect(addr, timeout, source_address):
        if addr[0] == "1.1.1.1":
            return FakeSocket()
        raise OSError("refused")

    assert probe_bypass(["1.1.1.1:443", "8.8.8.8:53"], connect=connect) == ["1.1.1.1:443"]


def test_probe_closes_leaked_sockets():
    socks: list[FakeSocket] = []

    def connect(addr, timeout, source_address):
        s = FakeSocket()
        socks.append(s)
        return s

    probe_bypass(["1.1.1.1:443"], connect=connect)
    assert socks and all(s.closed for s in socks)


@pytest.mark.parametrize(
    ("target", "expected"),
    [("1.1.1.1:443", ("1.1.1.1", 443)), ("[2606:4700::1111]:443", ("2606:4700::1111", 443))],
)
def test_parse_target(target, expected):
    assert parse_target(target) == expected


@pytest.mark.parametrize("target", ["1.1.1.1", "[::1]", ""])
def test_parse_target_rejects_missing_port(target):
    with pytest.raises(ValueError):
        parse_target(target)


# -- enablement policy -----------------------------------------------------------

@pytest.mark.parametrize(
    ("setting", "env", "expected"),
    [
        ("auto", "prod", True),
        ("auto", "dev", False),
        ("enabled", "dev", True),
        ("enabled", "prod", True),
        ("disabled", "prod", False),
        ("disabled", "dev", False),
    ],
)
def test_self_test_enabled_matrix(setting, env, expected):
    assert self_test_enabled(EgressConfig(bypass_self_test=setting), env) is expected


# -- runtime refusal (the acceptance test) ----------------------------------------

def _prod_runtime(tmp_path, probe_connect):
    key_path = tmp_path / "keys" / "mediator_ed25519"
    generate_signing_key(key_path)
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        "mode: balanced\nenv: prod\n"
        f"keys:\n  signing_key_path: {key_path.as_posix()}\n",
        encoding="utf-8",
    )
    return Runtime(cfg, data_dir=tmp_path / "data", probe_connect=probe_connect)


def test_bypass_success_refuses_start_and_receipts(tmp_path):
    with pytest.raises(EgressBypassError):
        _prod_runtime(tmp_path, _connect_success)

    # The refusal left signed evidence: a CRITICAL killswitch receipt.
    lines = (tmp_path / "data" / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    receipt = json.loads(lines[-1])
    assert receipt["action"] == "killswitch"
    assert receipt["verdict"] == "block"
    assert receipt["block_reason"] == "EGRESS_BYPASS_DETECTED"
    (f,) = receipt["findings"]
    assert f["severity"] == "critical" and f["rule_id"] == "egress.bypass_detected"


def test_bypass_all_blocked_boots_healthy(tmp_path):
    rt = _prod_runtime(tmp_path, _connect_refused)
    assert rt.healthz()["status"] == "healthy"
    rt.close()


def test_dev_auto_skips_probe(tmp_path):
    calls: list[tuple] = []

    def spy(addr, timeout, source_address):
        calls.append(addr)
        return FakeSocket()

    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("mode: balanced\nenv: dev\n", encoding="utf-8")
    rt = Runtime(cfg, data_dir=tmp_path / "data", probe_connect=spy)
    rt.close()
    assert calls == []  # dev laptops legitimately have direct internet


def test_dev_enabled_runs_probe_and_refuses(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        "mode: balanced\nenv: dev\negress:\n  bypass_self_test: enabled\n",
        encoding="utf-8",
    )
    with pytest.raises(EgressBypassError):
        Runtime(cfg, data_dir=tmp_path / "data", probe_connect=_connect_success)


# -- nftables rendering ------------------------------------------------------------

def test_ruleset_is_default_deny_via_al_core_only():
    rules = render_ruleset(al_core_ip="172.28.0.2", proxy_ports=(8080, 8888))
    assert "policy drop;" in rules
    assert "ip daddr 172.28.0.2 tcp dport { 8080, 8888 } accept" in rules
    assert "counter drop" in rules
    assert 'oifname "lo" accept' in rules
    assert "ct state established,related accept" in rules


def test_ruleset_dns_only_via_al_core():
    rules = render_ruleset(al_core_ip="172.28.0.2")
    assert "ip daddr 172.28.0.2 udp dport 53 accept" in rules


def test_ruleset_without_dns():
    rules = render_ruleset(al_core_ip="172.28.0.2", allow_dns_to_al_core=False)
    assert "udp dport 53" not in rules
