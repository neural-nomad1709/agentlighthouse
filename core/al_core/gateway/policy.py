"""EgressPolicy — the single decision point every L1 ingress mode calls.

Order matters and is fail-closed at each step:

1. URL shape (scheme / length / userinfo) — no network activity,
2. host allowlist (empty list = default-deny),
3. port allowlist,
4. DNS pin + SSRF address validation (resolve once, validate all, pin IP).

The caller receipts the returned :class:`Decision` and, on allow, connects to
``decision.pin.ip`` while presenting ``decision.pin.host`` in SNI/Host.
"""

from __future__ import annotations

from .decision import BlockReason, Decision, finding
from .dnspin import PinnedResolver, ResolveFn
from .ssrf import check_url, host_allowed


class EgressPolicy:
    def __init__(
        self,
        *,
        allow_hosts: list[str],
        allow_ports: list[int],
        url_max_len: int = 8192,
        block_private: bool = True,
        rebind_protection: bool = True,
        pin_ttl_s: float = 300.0,
        resolve: ResolveFn | None = None,
    ) -> None:
        self._allow_hosts = list(allow_hosts)
        self._allow_ports = list(allow_ports)
        self._url_max_len = url_max_len
        self.resolver = PinnedResolver(
            block_private=block_private,
            rebind_protection=rebind_protection,
            pin_ttl_s=pin_ttl_s,
            resolve=resolve,
        )

    def check_connect(self, host: str, port: int) -> Decision:
        """Decide a host:port connection (forward CONNECT, or a parsed URL)."""
        if not host_allowed(host, self._allow_hosts):
            return Decision.block(
                BlockReason.HOST_NOT_ALLOWED,
                [finding("egress_policy", "policy.host_not_allowed", "high", owasp="ASI02")],
            )
        if port not in self._allow_ports:
            return Decision.block(
                BlockReason.PORT_NOT_ALLOWED,
                [finding("egress_policy", "policy.port_not_allowed", "high", owasp="ASI02")],
            )
        return self.resolver.resolve_pin(host)

    def check_url(self, url: str) -> Decision:
        """Decide a full URL (fetch proxy). Returns allow with a Pin, or block."""
        shape = check_url(url, url_max_len=self._url_max_len)
        if isinstance(shape, Decision):
            return shape
        host, port = shape
        return self.check_connect(host, port)


__all__ = ["EgressPolicy"]
