"""L0 egress enforcement — boot bypass self-test + nftables ruleset.

The Edge Gate's OS half. The proxies (L1) only matter if the network makes
them the *only* road out; this package proves and enforces that:

* :mod:`~al_core.egress.selftest` — at boot, try to reach the internet
  **without** going through al-core. Any success means the choke-point is not
  actually a choke-point → signed CRITICAL receipt + refuse to start.
* :mod:`~al_core.egress.nftables` — render the default-deny nftables ruleset
  applied inside the agent netns (Linux enforcement; rendering is portable).
"""

from .nftables import render_ruleset
from .selftest import (
    EgressBypassError,
    parse_target,
    probe_bypass,
    self_test_enabled,
)

__all__ = [
    "EgressBypassError",
    "parse_target",
    "probe_bypass",
    "render_ruleset",
    "self_test_enabled",
]
