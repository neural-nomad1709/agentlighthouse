"""MCP tool-descriptor pinning + poisoning detection (L1/L4, ASI04/ASI01).

Two supply-chain defenses against MCP servers:

* **Pinning (rug-pull / drift):** the first time a tool descriptor is seen its
  canonical hash is pinned. If a later session presents the *same tool name*
  with a *different* descriptor, that is a rug-pull — the server swapped the
  behaviour behind a trusted name — and it is **blocked until re-approved**.
* **Poisoning:** a tool's ``description`` is untrusted text the model reads and
  acts on. A description carrying an injection payload ("ignore your
  instructions and…") is a tool-poisoning attack; it is scanned with the L2/L3
  content gate and blocked before the descriptor ever reaches the agent.

Pins persist as JSON so drift is detected across restarts.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..detect import ContentGate, ScanContext
from ..gateway.decision import BlockReason, Decision, finding


@dataclass(frozen=True)
class ToolDescriptor:
    """An MCP tool as advertised by a server."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] | None = None

    def canonical(self) -> str:
        """Stable serialization for hashing (sorted keys, no whitespace)."""
        return json.dumps(
            {"name": self.name, "description": self.description,
             "input_schema": self.input_schema or {}},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        )

    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()


def scan_descriptor(descriptor: ToolDescriptor, gate: ContentGate) -> Decision:
    """Content-scan a descriptor's text for tool-poisoning (injection).

    Runs name + description through the L2/L3 gate. A block verdict means the
    descriptor itself is hostile -> TOOL_POISONED (ASI01)."""
    text = f"{descriptor.name}\n{descriptor.description}"
    result = gate.scan_text(text, ScanContext(direction="inbound",
                                              target=f"tool:{descriptor.name}",
                                              content_type="text/plain"))
    if result.blocked:
        return Decision.block(
            BlockReason.TOOL_POISONED,
            [finding("mcp_poison", "mcp.tool_poisoning", "high", owasp="ASI01",
                     mitre="T1204")] + result.findings,
        )
    return Decision.allow()


class ToolPinner:
    """Pins tool descriptors and flags drift (rug-pull). Optional JSON persistence."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path else None
        self._pins: dict[str, str] = {}  # tool name -> pinned digest
        if self._path and self._path.exists():
            self._pins = json.loads(self._path.read_text(encoding="utf-8"))

    def _save(self) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._pins, indent=2), encoding="utf-8")

    def is_pinned(self, name: str) -> bool:
        return name in self._pins

    def check(self, descriptor: ToolDescriptor) -> Decision:
        """First sight -> pin + allow. Same digest -> allow. Changed -> block."""
        digest = descriptor.digest()
        pinned = self._pins.get(descriptor.name)
        if pinned is None:
            self._pins[descriptor.name] = digest
            self._save()
            return Decision.allow()
        if pinned == digest:
            return Decision.allow()
        return Decision.block(
            BlockReason.TOOL_DESCRIPTOR_DRIFT,
            [finding("mcp_pin", "mcp.descriptor_drift", "high", owasp="ASI04",
                     mitre="T1195")],
        )

    def approve(self, descriptor: ToolDescriptor) -> None:
        """Re-pin a tool to its current descriptor (operator un-blocks a drift)."""
        self._pins[descriptor.name] = descriptor.digest()
        self._save()

    def unpin(self, name: str) -> None:
        self._pins.pop(name, None)
        self._save()


__all__ = ["ToolDescriptor", "ToolPinner", "scan_descriptor"]
