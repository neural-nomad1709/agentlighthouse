"""A2A — mediated inter-agent messaging (ASI07).

The interface the blueprint committed to from Phase 0, now with a working
mediator behind it. An inter-agent message is treated exactly like any other
untrusted input: the peer's **Agent Card** is pinned (drift = a rug-pull, the
same attack MCP descriptors face), the card's own text is poison-scanned, the
payload runs through the L2/L3 content gate, and the session is checked for
**smuggling** (a session id reused across a different peer pair).

Nothing here re-implements detection — it reuses the ContentGate and the
ToolPinner-shaped pinning idea, so a partner who graduates from the demo
harness to a real multi-agent topology changes transports, not policy.
"""

from .envelope import AgentCard, AgentEnvelope
from .mediator import A2aMediator, A2aOutcome, CardPinner, SessionRegistry

__all__ = [
    "A2aMediator",
    "A2aOutcome",
    "AgentCard",
    "AgentEnvelope",
    "CardPinner",
    "SessionRegistry",
]
