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
import subprocess
import sys
import uuid

import pytest

from al_core.egress import render_ruleset

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="nftables/netns are Linux-only"),
    pytest.mark.skipif(
        sys.platform == "linux" and os.geteuid() != 0, reason="requires root (NET_ADMIN)"
    ),
    pytest.mark.skipif(shutil.which("nft") is None, reason="nft binary not installed"),
]

AL_CORE_IP = "10.200.0.2"
PROXY_PORT = 18080


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


def test_default_deny_enforced_in_netns(netns):
    """With the ruleset applied, an outbound connect inside the netns is dropped.

    The namespace has a veth to a host-side peer; without nftables the connect
    to the peer would at least be *routable*. With the ruleset it must fail —
    the peer is not al-core.
    """
    host_if, ns_if = f"v{netns[-6:]}h", f"v{netns[-6:]}n"
    try:
        assert _run("ip", "link", "add", host_if, "type", "veth", "peer", "name", ns_if).returncode == 0
        _run("ip", "link", "set", ns_if, "netns", netns)
        _run("ip", "addr", "add", "10.200.0.1/24", "dev", host_if)
        _run("ip", "link", "set", host_if, "up")
        _run("ip", "-n", netns, "addr", "add", "10.200.0.99/24", "dev", ns_if)
        _run("ip", "-n", netns, "link", "set", ns_if, "up")

        # Sanity: peer reachable BEFORE enforcement (proves routability).
        pre = _run(
            "ip", "netns", "exec", netns, "python3", "-c",
            "import socket; s=socket.socket(); s.settimeout(2);"
            "r=s.connect_ex(('10.200.0.1', 9)); print(r)",
        )
        # connect_ex to a closed port on a routable host: ECONNREFUSED (111),
        # which proves packets flow. After enforcement we expect a TIMEOUT.
        assert pre.stdout.strip() == "111", f"veth not routable: {pre.stdout} {pre.stderr}"

        rules = render_ruleset(al_core_ip=AL_CORE_IP, proxy_ports=(PROXY_PORT,))
        apply_proc = _run("ip", "netns", "exec", netns, "nft", "-f", "-", input_text=rules)
        assert apply_proc.returncode == 0, apply_proc.stderr

        post = _run(
            "ip", "netns", "exec", netns, "python3", "-c",
            "import socket, errno; s=socket.socket(); s.settimeout(2);\n"
            "try:\n"
            "    r=s.connect_ex(('10.200.0.1', 9)); print(r)\n"
            "except socket.timeout:\n"
            "    print('timeout')",
        )
        # Dropped (not refused): either connect_ex EAGAIN-ish code or timeout —
        # anything but 111 means the RST never came back, i.e. default-deny held.
        assert post.stdout.strip() != "111", "packets still flowing after default-deny"
    finally:
        _run("ip", "link", "delete", host_if)
