"""L1 protocol mediation — the Edge Gate's application half.

One service, multiple ingress modes (forward CONNECT proxy, fetch proxy,
OpenAI/Anthropic reverse proxy), all funnelled through a single
:class:`~al_core.gateway.policy.EgressPolicy` decision point: host allowlist →
SSRF network checks → DNS pinning. Every decision is receipted.
"""

from .decision import BlockReason, Decision
from .dnspin import Pin, PinnedResolver
from .forward import ForwardProxy
from .policy import EgressPolicy
from .ssrf import check_url, classify_ip, host_allowed
from .vkeys import BudgetLedger, VirtualKey, VirtualKeyStore

__all__ = [
    "BlockReason",
    "BudgetLedger",
    "Decision",
    "EgressPolicy",
    "ForwardProxy",
    "Pin",
    "PinnedResolver",
    "VirtualKey",
    "VirtualKeyStore",
    "check_url",
    "classify_ip",
    "host_allowed",
]
