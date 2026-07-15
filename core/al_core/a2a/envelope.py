"""A2A wire types: the Agent Card and the message envelope.

Both are *untrusted input*. The card is the peer's self-description — the A2A
analogue of an MCP tool descriptor, and it is attacked the same way: swapped
behind a trusted name (drift), or stuffed with an injection payload the reading
model will act on (poisoning). The envelope carries the payload plus the
session id, which is the smuggling surface.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass(frozen=True)
class AgentCard:
    """A peer agent's self-description (name, purpose, advertised skills)."""

    name: str
    description: str = ""
    skills: tuple[str, ...] = ()
    endpoint: str = ""

    def canonical(self) -> str:
        return json.dumps(
            {"name": self.name, "description": self.description,
             "skills": list(self.skills), "endpoint": self.endpoint},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        )

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()

    def text(self) -> str:
        """Everything a model would read — the poisoning surface."""
        return "\n".join([self.name, self.description, *self.skills])


@dataclass(frozen=True)
class AgentEnvelope:
    """One inter-agent message (the Phase-0 interface, unchanged)."""

    sender: str          # spiffe id of the sending agent
    recipient: str       # spiffe id of the receiving agent
    payload: str
    session_id: str = "default"
    protocol: Literal["a2a", "custom"] = "a2a"
    agent_card: AgentCard | None = None   # pinned + drift-checked, like MCP
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def peers(self) -> tuple[str, str]:
        """The unordered pair this session legitimately belongs to."""
        return tuple(sorted((self.sender, self.recipient)))  # type: ignore[return-value]


__all__ = ["AgentCard", "AgentEnvelope"]
