"""Taint tracking (L4) — untrusted ingestion tightens later decisions (ASI01).

A session that ingests untrusted content — a web fetch, an unpinned tool
result, content that tripped an injection scanner — becomes **tainted**. A
tainted session then faces tightened policy on subsequent *protected*
operations (the HITL gate widens; scanning escalates). This is the mechanism
that stops an indirect prompt injection read early in a session from quietly
driving an exfiltration later in it.

Taint is per-session, monotonic within a session (it does not clear itself —
only an explicit ``clear`` resets it), and records *why* it was set so the
receipt can explain the escalation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .store import CapabilityStore


class TaintSource:
    """Fixed vocabulary for why a session became tainted."""

    WEB_FETCH = "web_fetch"                 # ingested fetched web content
    UNPINNED_TOOL_RESULT = "unpinned_tool"  # tool output not descriptor-pinned
    INJECTION_DETECTED = "injection"        # content gate flagged injection
    UNTRUSTED_AGENT = "untrusted_agent"     # A2A / inter-agent message
    MEMORY_POISON = "memory_poison"         # hostile content found in the memory store


@dataclass
class TaintState:
    tainted: bool = False
    sources: list[str] = field(default_factory=list)


class TaintTracker:
    """Per-session taint state. Thread-safety is the caller's concern (the
    gateway serializes receipt writes; taint updates ride the same path)."""

    def __init__(self, *, store: CapabilityStore | None = None) -> None:
        self._sessions: dict[str, TaintState] = {}
        self._store = store
        if store is not None:
            # Rehydrate: taint is monotonic within a session, and a restart
            # must not launder it (that direction is fail-open).
            for session_id, sources in store.load_taint().items():
                self._sessions[session_id] = TaintState(
                    tainted=True, sources=list(sources))

    def mark(self, session_id: str, source: str) -> None:
        """Taint ``session_id`` (idempotent per source)."""
        state = self._sessions.setdefault(session_id, TaintState())
        state.tainted = True
        if source not in state.sources:
            state.sources.append(source)
        if self._store is not None:
            self._store.mark_taint(session_id, source)

    def is_tainted(self, session_id: str) -> bool:
        state = self._sessions.get(session_id)
        return bool(state and state.tainted)

    def state(self, session_id: str) -> TaintState:
        return self._sessions.get(session_id, TaintState())

    def sources(self, session_id: str) -> list[str]:
        return list(self.state(session_id).sources)

    def clear(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        if self._store is not None:
            self._store.clear_taint(session_id)


__all__ = ["TaintSource", "TaintState", "TaintTracker"]
