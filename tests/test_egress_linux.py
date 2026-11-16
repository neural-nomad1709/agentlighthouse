"""L0 enforcement integration tests — Linux + root + nft only.

These prove the rendered ruleset actually *enforces* (not merely parses):
inside a scratch network namespace with the ruleset applied, the only
permitted destination is the al-core address/ports; everything else is
dropped. Auto-skips on Windows/macOS, non-root, or missing nft — the same
pattern as the POSIX key-permission test.

Run on a Linux host / CI job:  sudo -E uv run pytest tests/test_egress_linux.py
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import uuid

import pytest

from al_core.egress import render_agent_uid_ruleset, render_ruleset
from al_core.egress.nftables import AGENT_UID_TABLE_NAME

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="nftables/netns are Linux-only"),
    pytest.mark.skipif(
        sys.platform == "linux" and os.geteuid() != 0, reason="requires root (NET_ADMIN)"
    ),
    pytest.mark.skipif(shutil.which("nft") is None, reason="nft binary not installed"),
]

AL_CORE_IP = "10.200.0.2"
PEER_IP = "10.200.0.1"
PROXY_PORT = 18080
OTHER_LOCAL_PORT = 18898  # stands in for any other service on the host
LISTEN_PORT = 18443
AGENT_UID = 61500  # needs no passwd entry: the kernel matches the number


def _run(*argv: str, input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv, input=input_text, capture_output=True, text=True, timeout=30
    )


def test_rendered_ruleset_is_valid_nft_syntax():
    rules = render_ruleset(al_core_ip=AL_CORE_IP, proxy_ports=(PROXY_PORT, 8888))
    proc = _run("nft", "--check", "-f", "-", input_text=rules)
    assert proc.returncode == 0, f"nft rejected the ruleset:\n{proc.stderr}"


@pytest.fixture
def netns():
    """Scratch network namespace with lo up; deleted afterwards."""
    name = f"al-test-{uuid.uuid4().hex[:8]}"
    assert _run("ip", "netns", "add", name).returncode == 0
    _run("ip", "-n", name, "link", "set", "lo", "up")
    yield name
    _run("ip", "netns", "delete", name)


@pytest.fixture
def routed_netns(netns):
    """The scratch namespace with a veth to a host-side peer at PEER_IP, so a
    connect to the peer is *routable* until a ruleset says otherwise."""
    host_if, ns_if = f"v{netns[-6:]}h", f"v{netns[-6:]}n"
    try:
        assert _run("ip", "link", "add", host_if, "type", "veth", "peer", "name", ns_if).returncode == 0
        _run("ip", "link", "set", ns_if, "netns", netns)
        _run("ip", "addr", "add", f"{PEER_IP}/24", "dev", host_if)
        _run("ip", "link", "set", host_if, "up")
        _run("ip", "-n", netns, "addr", "add", "10.200.0.99/24", "dev", ns_if)
        _run("ip", "-n", netns, "link", "set", ns_if, "up")
        yield netns
    finally:
        _run("ip", "link", "delete", host_if)


def _connect(netns: str, host: str, port: int, *, uid: int | None = None) -> str:
    """TCP connect inside the namespace (as ``uid`` when given) to a port
    nobody listens on. "111" (ECONNREFUSED) proves the packets flowed: the
    SYN left and the RST came back. Anything else means the SYN was dropped.
    """
    as_uid = () if uid is None else (
        "setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups")
    family = "AF_INET6" if ":" in host else "AF_INET"
    proc = _run(
        "ip", "netns", "exec", netns, *as_uid, "python3", "-c",
        f"import socket; s=socket.socket(socket.{family}); s.settimeout(2);\n"
        "try:\n"
        f"    print(s.connect_ex(({host!r}, {port})))\n"
        "except socket.timeout:\n"
        "    print('timeout')",
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def _apply(netns: str, rules: str) -> None:
    proc = _run("ip", "netns", "exec", netns, "nft", "-f", "-", input_text=rules)
    assert proc.returncode == 0, proc.stderr


def test_default_deny_enforced_in_netns(routed_netns):
    """With the ruleset applied, an outbound connect inside the netns is dropped.

    Without nftables the connect to the veth peer is routable. With the
    ruleset it must fail — the peer is not al-core.
    """
    assert _connect(routed_netns, PEER_IP, 9) == "111", "veth not routable"

    _apply(routed_netns, render_ruleset(al_core_ip=AL_CORE_IP, proxy_ports=(PROXY_PORT,)))

    assert _connect(routed_netns, PEER_IP, 9) != "111", "packets still flowing after default-deny"


# -- per-uid ruleset: mediator and agent on one host -------------------------------

needs_setpriv = pytest.mark.skipif(
    shutil.which("setpriv") is None, reason="setpriv (util-linux) not installed")


def test_agent_uid_ruleset_is_valid_nft_syntax():
    rules = render_agent_uid_ruleset(agent_uid=AGENT_UID, proxy_ports=(PROXY_PORT, 8443))
    proc = _run("nft", "--check", "-f", "-", input_text=rules)
    assert proc.returncode == 0, f"nft rejected the ruleset:\n{proc.stderr}"


@needs_setpriv
def test_agent_uid_is_confined_to_the_proxy_port(routed_netns):
    """The agent uid reaches the proxy port on loopback and nothing else."""
    # Before enforcement the agent uid reaches everything this test probes.
    assert _connect(routed_netns, "127.0.0.1", OTHER_LOCAL_PORT, uid=AGENT_UID) == "111"
    assert _connect(routed_netns, "::1", OTHER_LOCAL_PORT, uid=AGENT_UID) == "111"
    assert _connect(routed_netns, PEER_IP, 9, uid=AGENT_UID) == "111"

    _apply(routed_netns, render_agent_uid_ruleset(
        agent_uid=AGENT_UID, proxy_ports=(PROXY_PORT,)))

    assert _connect(routed_netns, "127.0.0.1", PROXY_PORT, uid=AGENT_UID) == "111", \
        "the agent cannot reach the proxy port"
    assert _connect(routed_netns, "127.0.0.1", OTHER_LOCAL_PORT, uid=AGENT_UID) != "111", \
        "the agent reached another local service"
    assert _connect(routed_netns, "::1", OTHER_LOCAL_PORT, uid=AGENT_UID) != "111", \
        "the agent reached another local service over IPv6"
    assert _connect(routed_netns, PEER_IP, 9, uid=AGENT_UID) != "111", \
        "the agent reached the network"


@needs_setpriv
def test_agent_uid_ruleset_leaves_other_uids_alone(routed_netns):
    """The mediator's own uid (root here, and any third uid) keeps its egress."""
    _apply(routed_netns, render_agent_uid_ruleset(
        agent_uid=AGENT_UID, proxy_ports=(PROXY_PORT,)))

    assert _connect(routed_netns, PEER_IP, 9) == "111"
    assert _connect(routed_netns, "127.0.0.1", OTHER_LOCAL_PORT) == "111"
    assert _connect(routed_netns, PEER_IP, 9, uid=AGENT_UID + 1) == "111"


@needs_setpriv
def test_agent_uid_ruleset_applied_twice_holds_one_copy(routed_netns):
    rules = render_agent_uid_ruleset(agent_uid=AGENT_UID, proxy_ports=(PROXY_PORT,))
    _apply(routed_netns, rules)
    _apply(routed_netns, rules)

    listing = _run("ip", "netns", "exec", routed_netns,
                   "nft", "list", "table", "inet", AGENT_UID_TABLE_NAME)
    assert listing.returncode == 0, listing.stderr
    assert listing.stdout.count("skuid") == 2, listing.stdout
    assert _connect(routed_netns, PEER_IP, 9, uid=AGENT_UID) != "111"


@needs_setpriv
def test_agent_uid_cannot_open_a_connection_that_worked_before(routed_netns):
    """What `al egress selftest` relies on when it runs as the agent uid: a
    live listener outside connects ("0") before the ruleset and not after."""
    listener = socket.create_server((PEER_IP, LISTEN_PORT))
    try:
        assert _connect(routed_netns, PEER_IP, LISTEN_PORT, uid=AGENT_UID) == "0"

        _apply(routed_netns, render_agent_uid_ruleset(
            agent_uid=AGENT_UID, proxy_ports=(PROXY_PORT,)))

        assert _connect(routed_netns, PEER_IP, LISTEN_PORT, uid=AGENT_UID) not in ("0", "111")
        assert _connect(routed_netns, PEER_IP, LISTEN_PORT) == "0"
    finally:
        listener.close()
