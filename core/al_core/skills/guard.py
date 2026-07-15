"""SkillGuard — screen + pin agent instruction files (SKILL.md, CLAUDE.md, ...).

One decision point, fail-closed, in this order:

1. **Size** — an instruction file past the cap is refused rather than scanned
   (a 50 MB "skill" is not a skill).
2. **Screen** — the text runs through the L2/L3 content gate. A blocking verdict
   means the file is hostile: `SKILL_POISONED`, and the *content is withheld*.
   A ``strip`` verdict redacts on delivery (a secret pasted into a CLAUDE.md is
   a leak, not a reason to stop the agent).
3. **Pin** — first sight pins the SHA-256. A later load of the same path with a
   different digest is a rug-pull: `SKILL_DRIFT`, blocked until an operator runs
   ``al skill approve``. Pins persist, so the check survives a restart.

Order matters: a poisoned file is never pinned. Pinning it first would let the
attack become the trusted baseline.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..capability.taint import TaintSource, TaintTracker
from ..detect import ContentGate, ScanContext
from ..gateway.decision import BlockReason, Decision, finding
from ..receipt import utcnow_iso

Recorder = Callable[..., Any]


def digest_of(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_file(path: Path) -> str:
    """The ONE way this module reads an instruction file.

    Bytes, decoded explicitly — never ``read_text()``, whose universal-newline
    translation would silently produce a different string (and therefore a
    different digest) from the same file on Windows. A pin computed one way and
    checked the other would make drift un-approvable, which is exactly the bug
    this helper exists to prevent.
    """
    return Path(path).read_bytes().decode("utf-8", errors="replace")


@dataclass
class SkillOutcome:
    """Result of loading one instruction file. ``text`` is what the agent may
    actually read (redacted when the verdict was strip); None when withheld."""

    decision: Decision
    text: str | None = None
    redaction: dict[str, int] | None = None

    @property
    def allowed(self) -> bool:
        return self.decision.allowed


class SkillPinner:
    """Pins instruction files by path -> digest. Drift = rug-pull."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path else None
        self._pins: dict[str, dict[str, str]] = {}
        if self._path and self._path.exists():
            self._pins = json.loads(self._path.read_text(encoding="utf-8"))

    def _save(self) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._pins, indent=2), encoding="utf-8")

    @staticmethod
    def _key(file: Path) -> str:
        return file.resolve().as_posix()

    def pinned(self, file: Path) -> str | None:
        entry = self._pins.get(self._key(file))
        return entry["digest"] if entry else None

    def check(self, file: Path, text: str) -> Decision:
        """First sight -> pin + allow. Same digest -> allow. Changed -> block."""
        digest = digest_of(text)
        pinned = self.pinned(file)
        if pinned is None:
            self.approve(file, text)
            return Decision.allow()
        if pinned == digest:
            return Decision.allow()
        return Decision.block(
            BlockReason.SKILL_DRIFT,
            [finding("skill_pin", "skill.drift", "high", owasp="ASI04",
                     mitre="T1195")],
        )

    def approve(self, file: Path, text: str | None = None) -> None:
        """Operator re-pins a file to its current content (un-blocks a drift).

        ``text`` defaults to the file's own bytes, read the same way ``load()``
        reads it — do not pass text read some other way."""
        content = text if text is not None else read_file(file)
        self._pins[self._key(file)] = {
            "digest": digest_of(content), "approved_ts": utcnow_iso()}
        self._save()

    def unpin(self, file: Path) -> None:
        self._pins.pop(self._key(file), None)
        self._save()

    def all_pins(self) -> dict[str, dict[str, str]]:
        return dict(self._pins)


class SkillGuard:
    def __init__(
        self,
        content_gate: ContentGate,
        *,
        pinner: SkillPinner | None = None,
        taint: TaintTracker | None = None,
        recorder: Recorder | None = None,
        max_bytes: int = 262_144,
    ) -> None:
        self._gate = content_gate
        self._pinner = pinner or SkillPinner()
        self._taint = taint or TaintTracker()
        self._record = recorder or (lambda **_: None)
        self._max_bytes = max_bytes

    @property
    def pinner(self) -> SkillPinner:
        return self._pinner

    def load(
        self, file: str | Path, *, actor: str = "agent", session_id: str = "default",
    ) -> SkillOutcome:
        """Screen + pin one instruction file. Returns what the agent may read."""
        path = Path(file)
        target = f"skill:{path.name}"

        if not path.exists():
            # Nothing to read is not a failure — an agent with no CLAUDE.md is
            # normal. (A *missing* pinned file is a different question; see the
            # `verify` sweep below.)
            return SkillOutcome(decision=Decision.allow(), text=None)

        if path.stat().st_size > self._max_bytes:
            return self._deny(actor, target, Decision.block(
                BlockReason.SKILL_SIZE_EXCEEDED,
                [finding("skill_guard", "skill.size_anomaly", "medium",
                         owasp="ASI04")]))

        text = read_file(path)

        # Screen BEFORE pinning: a poisoned file must never become the baseline.
        result = self._gate.scan_text(text, ScanContext(
            actor=actor, direction="inbound", target=target,
            content_type="text/markdown"))
        if result.blocked:
            self._taint.mark(session_id, TaintSource.INJECTION_DETECTED)
            return self._deny(actor, target, Decision.block(
                BlockReason.SKILL_POISONED,
                [finding("skill_guard", "skill.poisoned", "critical",
                         owasp="ASI01", mitre="T1204")] + result.findings),
                session=session_id)

        drift = self._pinner.check(path, text)
        if not drift.allowed:
            self._taint.mark(session_id, TaintSource.INJECTION_DETECTED)
            return self._deny(actor, target, drift, session=session_id)

        self._record(actor=actor, action="skill_load", target=target,
                     verdict=result.verdict, findings=result.findings or None,
                     redaction=result.redaction or None, session=session_id)
        return SkillOutcome(decision=Decision.allow(), text=result.text,
                            redaction=result.redaction or None)

    def load_all(
        self, files: list[str | Path], *, actor: str = "agent",
        session_id: str = "default",
    ) -> dict[str, SkillOutcome]:
        return {str(f): self.load(f, actor=actor, session_id=session_id)
                for f in files}

    def verify(self, actor: str = "operator") -> list[str]:
        """Re-check every pinned file against its digest. Returns drifted paths.

        Read-only (no quarantine, no re-pin) — the diagnostic behind
        ``al skill verify``; one receipt covers the sweep."""
        drifted = [
            p for p, entry in self._pinner.all_pins().items()
            if not Path(p).exists() or digest_of(read_file(Path(p))) != entry["digest"]
        ]
        self._record(
            actor=actor, action="skill_load", target="skill:verify",
            verdict="block" if drifted else "allow",
            block_reason=BlockReason.SKILL_DRIFT if drifted else None,
            findings=[finding("skill_pin", "skill.drift", "high", owasp="ASI04",
                              mitre="T1195") for _ in drifted] or None,
        )
        return drifted

    def _deny(self, actor: str, target: str, decision: Decision,
              *, session: str | None = None) -> SkillOutcome:
        self._record(actor=actor, action="skill_load", target=target,
                     verdict="block", block_reason=decision.block_reason,
                     findings=decision.findings, session=session)
        return SkillOutcome(decision=decision)


__all__ = ["SkillGuard", "SkillOutcome", "SkillPinner", "digest_of", "read_file"]
