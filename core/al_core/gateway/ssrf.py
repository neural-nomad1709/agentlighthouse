"""SSRF network layer — the address- and URL-shape half of the Edge Gate.

Blocks requests whose *destination* is inside the deployment rather than out
on the internet: cloud metadata (169.254.169.254), RFC 1918 private ranges,
loopback, link-local, CGNAT, multicast/reserved space — over IPv4, IPv6, and
the IPv4-in-IPv6 embeddings (mapped + NAT64) attackers use to dodge v4-only
filters. Also validates URL shape (scheme, length, userinfo smuggling) before
any network activity happens.

This module is pure functions over addresses/strings; the stateful parts
(DNS pinning, rebind detection) live in :mod:`al_core.gateway.dnspin`.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable
from urllib.parse import urlsplit

from .decision import BlockReason, Decision, finding

# Cloud instance metadata endpoint — the single highest-value SSRF target
# (credential theft). Called out separately for receipts (MITRE T1552.005).
METADATA_V4 = ipaddress.ip_address("169.254.169.254")

# label -> networks. Labels appear in finding rule_ids (ssrf.<label>).
_BLOCKED_V4: list[tuple[str, ipaddress.IPv4Network]] = [
    ("unspecified", ipaddress.ip_network("0.0.0.0/8")),
    ("private", ipaddress.ip_network("10.0.0.0/8")),
    ("cgnat", ipaddress.ip_network("100.64.0.0/10")),
    ("loopback", ipaddress.ip_network("127.0.0.0/8")),
    ("link_local", ipaddress.ip_network("169.254.0.0/16")),
    ("private", ipaddress.ip_network("172.16.0.0/12")),
    ("private", ipaddress.ip_network("192.168.0.0/16")),
    ("reserved", ipaddress.ip_network("198.18.0.0/15")),
    ("multicast", ipaddress.ip_network("224.0.0.0/4")),
    ("reserved", ipaddress.ip_network("240.0.0.0/4")),
]

_BLOCKED_V6: list[tuple[str, ipaddress.IPv6Network]] = [
    ("unspecified", ipaddress.ip_network("::/128")),
    ("loopback", ipaddress.ip_network("::1/128")),
    ("private", ipaddress.ip_network("fc00::/7")),  # ULA; covers fd00::/8
    ("link_local", ipaddress.ip_network("fe80::/10")),
    ("multicast", ipaddress.ip_network("ff00::/8")),
]

# IPv4-in-IPv6 embeddings: classify the embedded IPv4 address instead, so
# ::ffff:10.0.0.1 or 64:ff9b::a00:1 cannot smuggle a private v4 destination.
_NAT64 = ipaddress.ip_network("64:ff9b::/96")

ALLOWED_SCHEMES = frozenset({"http", "https"})


def classify_ip(ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Return a block label ("metadata", "private", ...) or None if routable-public."""
    addr = ipaddress.ip_address(ip) if isinstance(ip, str) else ip

    if isinstance(addr, ipaddress.IPv6Address):
        mapped = addr.ipv4_mapped
        if mapped is not None:
            return classify_ip(mapped)
        if addr in _NAT64:
            embedded = ipaddress.ip_address(int(addr) & 0xFFFFFFFF)
            return classify_ip(embedded) or "nat64"
        for label, net in _BLOCKED_V6:
            if addr in net:
                return label
        return None

    if addr == METADATA_V4:
        return "metadata"
    for label, net in _BLOCKED_V4:
        if addr in net:
            return label
    return None


def ssrf_finding(label: str) -> dict:
    """Receipt finding for one blocked-address class."""
    return finding(
        scanner="ssrf",
        rule_id=f"ssrf.{label}",
        severity="critical" if label == "metadata" else "high",
        owasp="ASI02",
        mitre="T1552.005" if label == "metadata" else None,
    )


def check_ips(ips: Iterable[str], *, block_private: bool = True) -> Decision:
    """Fail-closed check of a resolved address set: ANY blocked address blocks.

    A hostname resolving to a mix of public and private addresses is treated as
    hostile (attackers race mixed A-records); the whole set is rejected.
    """
    if not block_private:
        return Decision.allow()
    for ip in ips:
        label = classify_ip(ip)
        if label is not None:
            return Decision.block(BlockReason.SSRF_BLOCKED, [ssrf_finding(label)])
    return Decision.allow()


def host_allowed(host: str, allow_hosts: Iterable[str]) -> bool:
    """Case-insensitive allowlist match; ``*.suffix`` entries match subdomains.

    Empty allowlist = default-deny (nothing matches).
    """
    h = host.lower().rstrip(".")
    for entry in allow_hosts:
        e = entry.lower().rstrip(".")
        if e.startswith("*."):
            suffix = e[1:]  # ".example.com"
            if h.endswith(suffix) and h != suffix.lstrip("."):
                return True
        elif h == e:
            return True
    return False


def check_url(url: str, *, url_max_len: int = 8192) -> Decision | tuple[str, int]:
    """Validate URL shape with no network activity.

    Returns ``(host, port)`` when the URL is well-formed, or a block
    :class:`Decision` explaining the rejection. Address/allowlist checks are
    the caller's next step (:class:`~al_core.gateway.policy.EgressPolicy`).
    """
    if len(url) > url_max_len:
        return Decision.block(
            BlockReason.URL_TOO_LONG,
            [finding("egress_policy", "url.too_long", "medium", owasp="ASI02")],
        )
    try:
        parts = urlsplit(url)
    except ValueError:
        return Decision.block(
            BlockReason.INVALID_URL,
            [finding("egress_policy", "url.malformed", "medium", owasp="ASI02")],
        )
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        return Decision.block(
            BlockReason.SCHEME_NOT_ALLOWED,
            [finding("egress_policy", f"url.scheme.{parts.scheme or 'none'}", "high", owasp="ASI02")],
        )
    # user:pass@host is a classic SSRF parser-confusion vector — never legitimate here.
    if parts.username is not None or parts.password is not None:
        return Decision.block(
            BlockReason.INVALID_URL,
            [finding("egress_policy", "url.userinfo", "high", owasp="ASI02")],
        )
    try:
        host = parts.hostname
        port = parts.port
    except ValueError:  # non-numeric / out-of-range port
        return Decision.block(
            BlockReason.INVALID_URL,
            [finding("egress_policy", "url.port", "medium", owasp="ASI02")],
        )
    if not host:
        return Decision.block(
            BlockReason.INVALID_URL,
            [finding("egress_policy", "url.no_host", "medium", owasp="ASI02")],
        )
    if port is None:
        port = 443 if parts.scheme.lower() == "https" else 80
    return host, port


__all__ = [
    "ALLOWED_SCHEMES",
    "METADATA_V4",
    "check_ips",
    "check_url",
    "classify_ip",
    "host_allowed",
    "ssrf_finding",
]
