"""A2aMediator — one fail-closed decision point for an inter-agent message.

Order matters and mirrors the other gates:

1. **Identity** — sender and recipient must both be known (no identity → deny).
2. **Agent-Card poisoning** — the card's own text is run through L2/L3. A card
   that carries "ignore your instructions and…" is hostile *before* any payload
   arrives (ASI07 + ASI01).
3. **Agent-Card pinning** — first sight pins the card's digest; a later message
   presenting the *same peer* with a *different* card is a rug-pull, blocked
   until an operator re-approves. Identical to the MCP descriptor defence,
   because it is identical to the MCP attack.
4. **Session smuggling** — a session id belongs to the peer pair that opened
   it. A third agent replaying that id to inherit its context is smuggling:
   denied, and the receipt names both the owner and the impostor.
5. **Payload** — inter-agent content is untrusted like any web fetch: it runs
   through the content gate (block → withheld, strip → redacted on delivery)
   and **taints the receiving session** (``UNTRUSTED_AGENT``), so a later
   protected tool call in that session faces the tightened HITL gate.

Every decision is receipted as ``a2a_message``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..capability.taint import TaintSource, TaintTracker
from ..detect import ContentGate, ScanContext
from ..gateway.decision import BlockReason, Decision, finding
from .envelope import AgentCard, AgentEnvelope

Recorder = Callable[..., Any]


@dataclass
class A2aOutcome:
    """Result of mediating one message. ``payload`` is what the recipient may
    see (redacted when the verdict was strip); None when the message is denied."""

    decision: Decision
    payload: str | None = None
    redaction: dict[str, int] | None = None

    @property
    def allowed(self) -> bool:
        return self.decision.allowed


class SessionRegistry:
    """Which peer pair owns a session id (the anti-smuggling ledger).

    Persisted, because a smuggling attempt that only works after a restart is
    still a smuggling attempt."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path else None
        self._owners: dict[str, list[str]] = {}
        if self._path and self._path.exists():
            self._owners = json.loads(self._path.read_text(encoding="utf-8"))

    def _save(self) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._owners, indent=2), encoding="utf-8")

    def owner(self, session_id: str) -> tuple[str, str] | None:
        pair = self._owners.get(session_id)
        return (pair[0], pair[1]) if pair else None

    def check(self, envelope: AgentEnvelope) -> Decision:
        """First sight binds the session to its peer pair; a different pair on
        the same id is smuggling."""
        owner = self.owner(envelope.session_id)
        if owner is None:
            self._owners[envelope.session_id] = list(envelope.peers)
            self._save()
            return Decision.allow()
        if owner == envelope.peers:
            return Decision.allow()
        return Decision.block(
            BlockReason.A2A_SESSION_SMUGGLED,
            [finding("a2a_session", "a2a.session_smuggling", "critical",
                     owasp="ASI07", mitre="T1134")],
        )

    def forget(self, session_id: str) -> None:
        self._owners.pop(session_id, None)
        self._save()


class CardPinner:
    """Pins peer Agent Cards; drift = rug-pull (ASI07/ASI04)."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path else None
        self._pins: dict[str, str] = {}
        if self._path and self._path.exists():
            self._pins = json.loads(self._path.read_text(encoding="utf-8"))

    def _save(self) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._pins, indent=2), encoding="utf-8")

    def check(self, agent: str, card: AgentCard) -> Decision:
        digest = card.digest()
        pinned = self._pins.get(agent)
        if pinned is None:
            self._pins[agent] = digest
            self._save()
            return Decision.allow()
        if pinned == digest:
            return Decision.allow()
        return Decision.block(
            BlockReason.A2A_CARD_DRIFT,
            [finding("a2a_card", "a2a.card_drift", "high", owasp="ASI07",
                     mitre="T1195")],
        )

    def approve(self, agent: str, card: AgentCard) -> None:
        """Operator re-pins a peer after reviewing its new card."""
        self._pins[agent] = card.digest()
        self._save()

    def is_pinned(self, agent: str) -> bool:
        return agent in self._pins


class A2aMediator:
    def __init__(
        self,
        content_gate: ContentGate,
        *,
        pinner: CardPinner | None = None,
        sessions: SessionRegistry | None = None,
        taint: TaintTracker | None = None,
        recorder: Recorder | None = None,
        known_agent: Callable[[str], bool] | None = None,
    ) -> None:
        self._gate = content_gate
        self._pinner = pinner or CardPinner()
        self._sessions = sessions or SessionRegistry()
        self._taint = taint or TaintTracker()
        self._record = recorder or (lambda **_: None)
        self._known_agent = known_agent or (lambda a: bool(a))

    @property
    def taint(self) -> TaintTracker:
        return self._taint

    @property
    def pinner(self) -> CardPinner:
        return self._pinner

    def mediate(self, envelope: AgentEnvelope) -> A2aOutcome:
        target = f"a2a:{envelope.recipient}"

        # 1. Identity — an unnamed peer is not a peer.
        if not (self._known_agent(envelope.sender)
                and self._known_agent(envelope.recipient)):
            return self._deny(envelope, target, Decision.block(
                BlockReason.NO_IDENTITY,
                [finding("a2a", "a2a.no_identity", "high", owasp="ASI07")],
            ))

        # 2 + 3. The peer's card: poisoned text, then drift.
        if envelope.agent_card is not None:
            card = envelope.agent_card
            scan = self._gate.scan_text(card.text(), ScanContext(
                actor=envelope.sender, direction="inbound",
                target=f"a2a:card:{envelope.sender}"))
            if scan.blocked:
                self._taint.mark(envelope.session_id, TaintSource.UNTRUSTED_AGENT)
                return self._deny(envelope, target, Decision.block(
                    BlockReason.A2A_CARD_POISONED,
                    [finding("a2a_card", "a2a.card_poisoning", "critical",
                             owasp="ASI07", mitre="T1204")] + scan.findings,
                ))
            drift = self._pinner.check(envelope.sender, card)
            if not drift.allowed:
                return self._deny(envelope, target, drift)

        # 4. Session smuggling.
        smuggle = self._sessions.check(envelope)
        if not smuggle.allowed:
            return self._deny(envelope, target, smuggle)

        # 5. Payload — untrusted content, and it taints the session either way.
        result = self._gate.scan_text(envelope.payload, ScanContext(
            actor=envelope.sender, direction="inbound", target=target))
        self._taint.mark(envelope.session_id, TaintSource.UNTRUSTED_AGENT)
        if result.blocked:
            return self._deny(envelope, target, Decision.block(
                BlockReason.A2A_MESSAGE_BLOCKED,
                [finding("a2a", "a2a.payload_blocked", "high", owasp="ASI07")]
                + result.findings,
            ))

        self._record(actor=envelope.sender, action="a2a_message", target=target,
                     verdict=result.verdict, findings=result.findings,
                     redaction=result.redaction or None,
                     session=envelope.session_id)
        return A2aOutcome(decision=Decision.allow(), payload=result.text,
                          redaction=result.redaction or None)

    def _deny(self, envelope: AgentEnvelope, target: str,
              decision: Decision) -> A2aOutcome:
        self._record(actor=envelope.sender or "anonymous", action="a2a_message",
                     target=target, verdict="block",
                     block_reason=decision.block_reason, findings=decision.findings,
                     session=envelope.session_id)
        return A2aOutcome(decision=decision)


__all__ = ["A2aMediator", "A2aOutcome", "CardPinner", "SessionRegistry"]
