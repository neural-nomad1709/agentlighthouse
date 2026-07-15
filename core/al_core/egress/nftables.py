"""nftables default-deny ruleset for the agent netns (L0).

Rendering is pure string work (testable anywhere); *applying* it requires
Linux with ``NET_ADMIN`` (``nft -f``), done by ``al egress nftables --apply``
inside the agent netns or its container entrypoint.

The rendered policy is the L0 invariant in rule form: the **only** road out
of the agent network is al-core. Everything else — including DNS, so agents
cannot even resolve names except through the mediator — is dropped.
"""

from __future__ import annotations

from typing import Iterable

TABLE_NAME = "al_egress"


def render_ruleset(
    *,
    al_core_ip: str,
    proxy_ports: Iterable[int] = (8080, 8888),
    allow_dns_to_al_core: bool = True,
) -> str:
    """Default-deny output ruleset: loopback + established + al-core only."""
    ports = ", ".join(str(p) for p in proxy_ports)
    lines = [
        f"table inet {TABLE_NAME} {{",
        "    chain output {",
        "        type filter hook output priority 0; policy drop;",
        "",
        "        # Return traffic for connections al-core already allowed.",
        "        ct state established,related accept",
        "",
        "        # Local IPC stays local.",
        '        oifname "lo" accept',
        "",
        "        # The single permitted road out: al-core's proxy ports.",
        f"        ip daddr {al_core_ip} tcp dport {{ {ports} }} accept",
    ]
    if allow_dns_to_al_core:
        lines += [
            "",
            "        # DNS only via al-core (rebinding defence pairs with dnspin).",
            f"        ip daddr {al_core_ip} udp dport 53 accept",
            f"        ip daddr {al_core_ip} tcp dport 53 accept",
        ]
    lines += [
        "",
        "        # Everything else — including direct DNS — is dropped.",
        "        counter drop",
        "    }",
        "}",
        "",
    ]
    return "\n".join(lines)


__all__ = ["TABLE_NAME", "render_ruleset"]
