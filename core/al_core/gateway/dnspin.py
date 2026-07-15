"""DNS pinning — resolve once, validate every address, pin the IP.

Kills DNS rebinding: the attacker's pattern is to answer the first resolution
with a public IP (passing validation) and a later resolution with a private IP
(reaching internal services). The mediator therefore:

1. resolves a hostname **once**, validates the *entire* address set against the
   SSRF layer (any blocked address → block the whole set),
2. **pins** one validated IP and connects to that literal IP for the pin's
   lifetime (SNI/Host still carry the hostname), and
3. on re-resolution after expiry, treats a public→blocked flip as a rebinding
   attack (``DNS_REBIND_BLOCKED``) rather than a plain SSRF block.

Failures fail closed: no resolution → block (``DNS_RESOLUTION_FAILED``).
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Callable

from .decision import BlockReason, Decision, finding
from .ssrf import classify_ip, ssrf_finding

# resolve(host) -> list of IP strings. Injectable for tests / custom resolvers.
ResolveFn = Callable[[str], list[str]]


def system_resolve(host: str) -> list[str]:
    """Default resolver: all A/AAAA addresses via getaddrinfo, order-preserving."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    ips: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in ips:
            ips.append(ip)
    return ips


@dataclass(frozen=True)
class Pin:
    """A validated, pinned resolution: connect to ``ip``; present ``host`` in SNI/Host."""

    host: str
    ip: str
    all_ips: tuple[str, ...]
    expires: float  # monotonic deadline


class PinnedResolver:
    """Stateful pin cache with rebind detection. One instance per gateway."""

    def __init__(
        self,
        *,
        block_private: bool = True,
        rebind_protection: bool = True,
        pin_ttl_s: float = 300.0,
        resolve: ResolveFn | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._block_private = block_private
        self._rebind_protection = rebind_protection
        self._ttl = pin_ttl_s
        self._resolve = resolve or system_resolve
        self._clock = clock
        self._pins: dict[str, Pin] = {}
        # Hosts that ever pinned clean — a later blocked resolution of one of
        # these is the rebind signature (kept past pin expiry on purpose).
        self._seen_public: set[str] = set()

    def resolve_pin(self, host: str) -> Decision:
        """Resolve + validate + pin. Returns an allow Decision carrying the Pin."""
        host = host.lower().rstrip(".")

        # Literal IP: nothing to resolve or rebind; just classify.
        try:
            label = classify_ip(host)
        except ValueError:
            label = "unresolved"  # not an IP literal — resolve below
        else:
            if label is not None and self._block_private:
                return Decision.block(BlockReason.SSRF_BLOCKED, [ssrf_finding(label)])
            return Decision.allow(
                Pin(host=host, ip=host, all_ips=(host,), expires=self._clock() + self._ttl)
            )

        now = self._clock()
        cached = self._pins.get(host)
        if cached is not None and cached.expires > now:
            return Decision.allow(cached)

        try:
            ips = self._resolve(host)
        except OSError:
            ips = []
        if not ips:
            return Decision.block(
                BlockReason.DNS_RESOLUTION_FAILED,
                [finding("ssrf", "dns.resolution_failed", "medium", owasp="ASI02")],
            )

        if self._block_private:
            blocked = None
            for ip in ips:
                blocked = classify_ip(ip)
                if blocked is not None:
                    break
            if blocked is not None:
                if self._rebind_protection and host in self._seen_public:
                    # Was public before, resolves blocked now: rebinding attack.
                    return Decision.block(
                        BlockReason.DNS_REBIND_BLOCKED,
                        [finding("ssrf", "dns.rebind", "critical", owasp="ASI02")],
                    )
                return Decision.block(BlockReason.SSRF_BLOCKED, [ssrf_finding(blocked)])

        pin = Pin(host=host, ip=ips[0], all_ips=tuple(ips), expires=now + self._ttl)
        self._pins[host] = pin
        self._seen_public.add(host)
        return Decision.allow(pin)

    def verify_pin(self, host: str, ip: str) -> bool:
        """Re-verify on connect: is ``ip`` still the pinned address for ``host``?"""
        pin = self._pins.get(host.lower().rstrip("."))
        return pin is not None and pin.ip == ip and pin.expires > self._clock()


__all__ = ["Pin", "PinnedResolver", "ResolveFn", "system_resolve"]
