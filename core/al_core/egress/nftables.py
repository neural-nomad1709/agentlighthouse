"""nftables default-deny rulesets for agents (L0).

Rendering is pure string work (testable anywhere); *applying* it requires
Linux with ``NET_ADMIN`` (``nft -f``), done by ``al egress nftables --apply``.

Two topologies, one invariant: the **only** road out for an agent is al-core.
Everything else — including DNS, so agents cannot even resolve names except
through the mediator — is dropped.

* :func:`render_ruleset` — the agent has a network namespace of its own. The
  whole namespace is default-deny; applied inside it or by its container
  entrypoint.
* :func:`render_agent_uid_ruleset` — the agent shares a host (and a network
  namespace) with the mediator. Only packets from the agent's uid are
  confined; applied once on the host.
"""

from __future__ import annotations

from typing import Iterable

TABLE_NAME = "al_egress"
AGENT_UID_TABLE_NAME = "al_egress_agent"


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


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def render_agent_uid_ruleset(*, agent_uid: int, proxy_ports: Iterable[int]) -> str:
    """Confine one uid to al-core's proxy ports on loopback; drop the rest.

    For a host where the mediator and the agent run side by side. The chain
    policy stays ``accept`` and both rules match the agent uid only, so the
    mediator and every other account keep their egress.

    The agent uid gets no ``established`` rule: it may open connections to
    the proxy ports and nothing else, so a connection opened *to* an agent
    process from outside gets no reply. It gets no DNS either: an agent behind
    the proxy never needs to resolve a name itself.
    """
    if not _is_int(agent_uid) or agent_uid <= 0:
        # uid 0 can delete the ruleset, so a rule for it would confine nothing.
        raise ValueError(f"agent uid must be a positive integer, got {agent_uid!r}")
    ports = list(proxy_ports)
    if not ports or not all(_is_int(p) and 0 < p < 65536 for p in ports):
        raise ValueError(f"proxy ports must be 1-65535 and not empty, got {ports!r}")
    port_set = ", ".join(str(p) for p in ports)
    lines = [
        # Declare-then-delete makes the file replace an earlier copy of the
        # table in one transaction, so applying it at every boot never stacks
        # duplicate rules and never leaves a moment without them.
        f"table inet {AGENT_UID_TABLE_NAME}",
        f"delete table inet {AGENT_UID_TABLE_NAME}",
        f"table inet {AGENT_UID_TABLE_NAME} {{",
        "    chain output {",
        "        type filter hook output priority 0; policy accept;",
        "",
        "        # The single permitted road out for the agent: al-core's proxy",
        "        # ports on this host.",
        f'        meta skuid {agent_uid} oifname "lo" tcp dport {{ {port_set} }} accept',
        "",
        "        # Everything else the agent sends is dropped: other local",
        "        # services, DNS, the network.",
        f"        meta skuid {agent_uid} counter drop",
        "    }",
        "}",
        "",
    ]
    return "\n".join(lines)


__all__ = [
    "AGENT_UID_TABLE_NAME",
    "TABLE_NAME",
    "render_agent_uid_ruleset",
    "render_ruleset",
]
