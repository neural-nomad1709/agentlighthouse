"""DNS pinning + rebind protection (ssrf_test — Phase 1 acceptance)."""

from __future__ import annotations

from al_core.gateway.decision import BlockReason
from al_core.gateway.dnspin import PinnedResolver


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class CountingResolver:
    """Scriptable resolver: pops answer sets in order, repeats the last one."""

    def __init__(self, *answers: list[str]) -> None:
        self.answers = list(answers)
        self.calls = 0

    def __call__(self, host: str) -> list[str]:
        self.calls += 1
        if len(self.answers) > 1:
            return self.answers.pop(0)
        return self.answers[0]


def _resolver(answers: CountingResolver, clock: FakeClock, **kw) -> PinnedResolver:
    defaults = dict(pin_ttl_s=300.0, resolve=answers, clock=clock)
    defaults.update(kw)
    return PinnedResolver(**defaults)


def test_resolve_once_then_served_from_pin():
    clock, res = FakeClock(), CountingResolver(["1.1.1.1"])
    r = _resolver(res, clock)
    d1 = r.resolve_pin("example.com")
    d2 = r.resolve_pin("example.com")
    assert d1.allowed and d2.allowed
    assert d1.pin.ip == d2.pin.ip == "1.1.1.1"
    assert res.calls == 1  # second call served from the pin, no re-resolution


def test_rebind_public_then_private_blocked():
    # Classic rebinding: first answer public (passes), later answer private.
    clock, res = FakeClock(), CountingResolver(["93.184.216.34"], ["10.0.0.1"])
    r = _resolver(res, clock)
    assert r.resolve_pin("evil.com").allowed
    clock.now += 301  # expire the pin, forcing re-resolution
    d = r.resolve_pin("evil.com")
    assert d.block_reason == BlockReason.DNS_REBIND_BLOCKED
    (f,) = d.findings
    assert f["rule_id"] == "dns.rebind" and f["severity"] == "critical"


def test_first_contact_private_is_ssrf_not_rebind():
    clock, res = FakeClock(), CountingResolver(["192.168.1.10"])
    d = _resolver(res, clock).resolve_pin("internal.host")
    assert d.block_reason == BlockReason.SSRF_BLOCKED


def test_mixed_answer_set_blocked():
    clock, res = FakeClock(), CountingResolver(["1.1.1.1", "127.0.0.1"])
    d = _resolver(res, clock).resolve_pin("mixed.com")
    assert d.block_reason == BlockReason.SSRF_BLOCKED


def test_resolution_failure_fails_closed():
    clock = FakeClock()

    def boom(host: str) -> list[str]:
        raise OSError("no dns")

    d = _resolver(boom, clock).resolve_pin("nowhere.invalid")  # type: ignore[arg-type]
    assert d.block_reason == BlockReason.DNS_RESOLUTION_FAILED


def test_empty_resolution_fails_closed():
    clock, res = FakeClock(), CountingResolver([])
    d = _resolver(res, clock).resolve_pin("empty.com")
    assert d.block_reason == BlockReason.DNS_RESOLUTION_FAILED


def test_literal_private_ip_blocked_without_resolution():
    clock, res = FakeClock(), CountingResolver(["should-not-be-called"])
    d = _resolver(res, clock).resolve_pin("10.0.0.5")
    assert d.block_reason == BlockReason.SSRF_BLOCKED
    assert res.calls == 0


def test_literal_public_ip_pins_itself():
    clock, res = FakeClock(), CountingResolver(["should-not-be-called"])
    d = _resolver(res, clock).resolve_pin("1.1.1.1")
    assert d.allowed and d.pin.ip == "1.1.1.1"
    assert res.calls == 0


def test_block_private_disabled_allows_private_resolution():
    clock, res = FakeClock(), CountingResolver(["10.0.0.1"])
    d = _resolver(res, clock, block_private=False).resolve_pin("internal.host")
    assert d.allowed and d.pin.ip == "10.0.0.1"


def test_verify_pin_on_connect():
    clock, res = FakeClock(), CountingResolver(["1.1.1.1"])
    r = _resolver(res, clock)
    r.resolve_pin("example.com")
    assert r.verify_pin("example.com", "1.1.1.1")
    assert not r.verify_pin("example.com", "2.2.2.2")  # not the pinned address
    clock.now += 301
    assert not r.verify_pin("example.com", "1.1.1.1")  # pin expired
