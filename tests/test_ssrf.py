"""SSRF network layer (ssrf_test — Phase 1 acceptance).

Metadata IP + private CIDRs blocked over IPv4, IPv6, and v4-in-v6 embeddings;
URL shape validated before any network activity; allowlist cannot override an
SSRF block (scanner-block-wins).
"""

from __future__ import annotations

import pytest

from al_core.gateway import EgressPolicy
from al_core.gateway.decision import BlockReason, Decision
from al_core.gateway.ssrf import check_ips, check_url, classify_ip, host_allowed


# -- address classification --------------------------------------------------

def test_metadata_ip_blocked_and_labelled():
    assert classify_ip("169.254.169.254") == "metadata"


@pytest.mark.parametrize(
    ("ip", "label"),
    [
        ("10.1.2.3", "private"),
        ("172.16.5.5", "private"),
        ("172.31.255.255", "private"),
        ("192.168.1.1", "private"),
        ("127.0.0.1", "loopback"),
        ("127.255.255.254", "loopback"),
        ("169.254.0.1", "link_local"),
        ("100.64.0.1", "cgnat"),
        ("0.0.0.1", "unspecified"),
        ("198.18.0.1", "reserved"),
        ("224.0.0.1", "multicast"),
        ("240.0.0.1", "reserved"),
        ("255.255.255.255", "reserved"),
    ],
)
def test_private_v4_cidrs_blocked(ip, label):
    assert classify_ip(ip) == label


@pytest.mark.parametrize("ip", ["1.1.1.1", "8.8.8.8", "93.184.216.34"])
def test_public_v4_allowed(ip):
    assert classify_ip(ip) is None


@pytest.mark.parametrize(
    ("ip", "label"),
    [
        ("::1", "loopback"),
        ("::", "unspecified"),
        ("fd00::1", "private"),
        ("fc00::1", "private"),
        ("fe80::1", "link_local"),
        ("ff02::1", "multicast"),
    ],
)
def test_blocked_v6(ip, label):
    assert classify_ip(ip) == label


def test_public_v6_allowed():
    assert classify_ip("2606:4700:4700::1111") is None


def test_v4_mapped_v6_unwrapped():
    # ::ffff:<v4> must classify as the embedded v4, not slip past v4 filters.
    assert classify_ip("::ffff:10.0.0.1") == "private"
    assert classify_ip("::ffff:169.254.169.254") == "metadata"
    assert classify_ip("::ffff:1.1.1.1") is None


def test_nat64_always_blocked():
    # NAT64 with an embedded private v4 reports the embedded class; NAT64 with
    # a public v4 is still blocked (unusual encoding, no legitimate use here).
    assert classify_ip("64:ff9b::a00:1") == "private"  # 10.0.0.1
    assert classify_ip("64:ff9b::101:101") == "nat64"  # 1.1.1.1


def test_mixed_resolution_set_blocked():
    d = check_ips(["1.1.1.1", "10.0.0.1"])
    assert d.verdict == "block" and d.block_reason == BlockReason.SSRF_BLOCKED


def test_check_ips_permissive_when_disabled():
    assert check_ips(["10.0.0.1"], block_private=False).allowed


def test_metadata_finding_is_critical_with_mitre():
    d = check_ips(["169.254.169.254"])
    (f,) = d.findings
    assert f["severity"] == "critical" and f["mitre"] == "T1552.005" and f["owasp"] == "ASI02"


# -- host allowlist ----------------------------------------------------------

def test_empty_allowlist_is_default_deny():
    assert not host_allowed("example.com", [])


def test_exact_match_case_insensitive():
    assert host_allowed("API.Example.COM", ["api.example.com"])


def test_wildcard_matches_subdomain_not_apex_or_lookalike():
    allow = ["*.example.com"]
    assert host_allowed("sub.example.com", allow)
    assert host_allowed("a.b.example.com", allow)
    assert not host_allowed("example.com", allow)
    assert not host_allowed("evilexample.com", allow)


# -- URL shape ---------------------------------------------------------------

@pytest.mark.parametrize("url", ["file:///etc/passwd", "gopher://x/", "ftp://x/"])
def test_non_http_scheme_blocked(url):
    d = check_url(url)
    assert isinstance(d, Decision) and d.block_reason == BlockReason.SCHEME_NOT_ALLOWED


def test_url_too_long_blocked():
    d = check_url("https://example.com/" + "a" * 9000, url_max_len=8192)
    assert isinstance(d, Decision) and d.block_reason == BlockReason.URL_TOO_LONG


def test_userinfo_smuggling_blocked():
    d = check_url("https://trusted.com@10.0.0.1/")
    assert isinstance(d, Decision) and d.block_reason == BlockReason.INVALID_URL


def test_missing_host_blocked():
    d = check_url("https:///path")
    assert isinstance(d, Decision) and d.block_reason == BlockReason.INVALID_URL


def test_out_of_range_port_blocked():
    d = check_url("https://example.com:99999/")
    assert isinstance(d, Decision) and d.block_reason == BlockReason.INVALID_URL


def test_default_ports_applied():
    assert check_url("https://example.com/x") == ("example.com", 443)
    assert check_url("http://example.com/x") == ("example.com", 80)
    assert check_url("https://example.com:8443/x") == ("example.com", 8443)


# -- EgressPolicy composition -------------------------------------------------

def _policy(**kw) -> EgressPolicy:
    defaults = dict(
        allow_hosts=["api.example.com"],
        allow_ports=[443],
        resolve=lambda host: ["93.184.216.34"],
    )
    defaults.update(kw)
    return EgressPolicy(**defaults)


def test_policy_blocks_unlisted_host():
    d = _policy().check_url("https://other.com/x")
    assert d.block_reason == BlockReason.HOST_NOT_ALLOWED


def test_policy_blocks_unlisted_port():
    d = _policy().check_url("https://api.example.com:8443/x")
    assert d.block_reason == BlockReason.PORT_NOT_ALLOWED


def test_policy_allows_listed_host_with_pin():
    d = _policy().check_url("https://api.example.com/x")
    assert d.allowed and d.pin is not None
    assert d.pin.ip == "93.184.216.34" and d.pin.host == "api.example.com"


def test_allowlist_cannot_override_ssrf_block():
    # Even an allowlisted host is blocked if it resolves inside the perimeter.
    d = _policy(resolve=lambda host: ["169.254.169.254"]).check_url(
        "https://api.example.com/x"
    )
    assert d.block_reason == BlockReason.SSRF_BLOCKED


def test_literal_metadata_ip_blocked_despite_allowlist():
    d = _policy(allow_hosts=["169.254.169.254"]).check_url("https://169.254.169.254/latest")
    assert d.block_reason == BlockReason.SSRF_BLOCKED
