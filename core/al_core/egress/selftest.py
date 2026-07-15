"""Boot bypass self-test — prove the choke-point is real before serving.

Attempts direct TCP connections to known-external targets *bypassing* al-core
(no proxy). In a correctly deployed agent network none of them can succeed —
`agent-net` is internal and nftables default-denies everything else. Any
success is a broken deployment: the caller records a signed CRITICAL receipt
and **refuses to start** (Phase 1 acceptance; failure-mode table row
"egress bypass succeeds at boot → refuse start").

Where it runs: inside the agent netns (``al egress selftest`` as an agent
entrypoint precondition), or by al-core itself with ``source_address`` bound
to its agent-net interface so the probe leaves via the agent-side leg.

``auto`` policy resolves to enabled only in ``env: prod`` — a dev laptop has
legitimate direct internet, so probing there would always "fail".
"""

from __future__ import annotations

import socket
from typing import Callable, Iterable

from ..config import EgressConfig

# connect((host, port), timeout, source_address) -> closeable | raises OSError.
ConnectFn = Callable[[tuple[str, int], float, tuple[str, int] | None], object]


class EgressBypassError(RuntimeError):
    """Out-of-band egress succeeded — the deployment is not a choke-point."""


def _default_connect(
    addr: tuple[str, int], timeout: float, source_address: tuple[str, int] | None
) -> object:
    return socket.create_connection(addr, timeout=timeout, source_address=source_address)


def parse_target(target: str) -> tuple[str, int]:
    """"1.1.1.1:443" / "[2606::1]:443" -> (host, port)."""
    if target.startswith("["):
        host, sep, port_s = target.rpartition("]:")
        if not sep:
            raise ValueError(f"IPv6 probe target missing port: {target!r}")
        return host.lstrip("["), int(port_s)
    host, sep, port_s = target.rpartition(":")
    if not sep:
        raise ValueError(f"probe target missing port: {target!r}")
    return host, int(port_s)


def self_test_enabled(egress: EgressConfig, env: str) -> bool:
    if egress.bypass_self_test == "enabled":
        return True
    return egress.bypass_self_test == "auto" and env == "prod"


def probe_bypass(
    targets: Iterable[str],
    *,
    timeout_s: float = 3.0,
    source_address: tuple[str, int] | None = None,
    connect: ConnectFn | None = None,
) -> list[str]:
    """Return the targets that CONNECTED out-of-band (non-empty = broken).

    A connection *failure* is the healthy outcome here; only refusals/timeouts
    prove the default-deny is in effect.
    """
    do_connect = connect or _default_connect
    reached: list[str] = []
    for target in targets:
        host, port = parse_target(target)
        try:
            conn = do_connect((host, port), timeout_s, source_address)
        except OSError:
            continue  # no route out — exactly what we want
        reached.append(target)
        close = getattr(conn, "close", None)
        if close is not None:
            try:
                close()
            except OSError:  # pragma: no cover — best-effort cleanup
                pass
    return reached


__all__ = [
    "ConnectFn",
    "EgressBypassError",
    "parse_target",
    "probe_bypass",
    "self_test_enabled",
]
