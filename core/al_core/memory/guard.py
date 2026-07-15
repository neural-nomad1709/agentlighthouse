"""MemoryGuard (L5) — screen every memory read/write; detect tamper; roll back.

Memory is where a poisoned entry outlives the session that planted it (ASI06):
an injection written today quietly steers every future step that reads it.
The guard mediates the store the way the gateway mediates the network:

* **Writes** are screened through the L2/L3 content gate before they land.
  Verdicts map to the four memory actions: allow -> stored, strip ->
  **redacted** then stored, block -> **blocked + quarantined** (the payload is
  preserved for forensics in a separate file, never in the active store).
  Oversized values are a size anomaly and are denied outright.
* **Protected keys** (glob patterns; e.g. ``system/*``) carry SHA-256
  integrity baselines in a mediator-owned file separate from the store. Only
  trusted writers may change them through the guard; an out-of-band edit —
  the file changed underneath us — is a **baseline mismatch on read**:
  blocked, quarantined, receipted critical (``PROTECTED_KEY_TAMPERED``).
* **Reads** are screened too (poison that predates the guard, or landed
  out-of-band on an unprotected key): block -> withheld + quarantined,
  strip -> redacted on delivery (the store is not rewritten by a read).
* **Snapshot + rollback**: a snapshot captures store + baselines as
  known-good; rollback restores it and reports before/after store hashes.
* Hostile memory content **taints the session** (L4), so a later protected
  tool call in the same session faces the tightened HITL gate.

The screening engine is the Phase-2 ``Scanner``/``ContentGate`` contract —
the OWASP Agent Memory Guard engine graduates in as a Scanner adapter without
touching this module. Audit-mode semantics ride the gate (would-be blocks are
observed, not enforced); the guard's own checks — protected-key writes, size
anomaly, integrity baselines — are not scans and always enforce: a guard
whose trust base is tampered cannot claim to observe.

Every decision is receipted (``memory_read`` / ``memory_write``).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Callable

from ..capability.taint import TaintSource, TaintTracker
from ..detect import ContentGate, ScanContext
from ..gateway.decision import BlockReason, Decision, finding
from ..receipt import utcnow_iso
from .store import MemoryEntry, MemoryStore, value_hash

Recorder = Callable[..., Any]


@dataclass
class MemoryResult:
    """Outcome of one guarded memory operation. ``value`` is the delivered
    content on reads (redacted when the verdict is strip); None when blocked
    or on writes."""

    decision: Decision
    value: str | None = None
    redaction: dict[str, int] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision.allowed


@dataclass(frozen=True)
class SnapshotInfo:
    snapshot_id: str
    path: Path
    store_hash: str
    keys: list[str]


@dataclass(frozen=True)
class RollbackInfo:
    snapshot_id: str
    before_hash: str
    after_hash: str
    restored_keys: list[str]


class MemoryGuard:
    def __init__(
        self,
        store: MemoryStore,
        *,
        content_gate: ContentGate,
        baseline_path: Path,
        quarantine_path: Path,
        snapshot_dir: Path,
        protected_keys: list[str] | None = None,
        trusted_writers: set[str] | None = None,
        max_value_bytes: int = 65_536,
        recorder: Recorder | None = None,
        taint: TaintTracker | None = None,
    ) -> None:
        self._store = store
        self._gate = content_gate
        self._baseline_path = Path(baseline_path)
        self._quarantine_path = Path(quarantine_path)
        self._snapshot_dir = Path(snapshot_dir)
        self._protected = list(protected_keys or [])
        self._trusted = set(trusted_writers or set())
        self._max_bytes = max_value_bytes
        self._record = recorder or (lambda **_: None)
        self._taint = taint or TaintTracker()
        self._baselines: dict[str, str] = {}
        if self._baseline_path.exists():
            self._baselines = json.loads(self._baseline_path.read_text(encoding="utf-8"))

    # -- protected keys ------------------------------------------------------

    def is_protected(self, key: str) -> bool:
        return any(fnmatch(key, pattern) for pattern in self._protected)

    def _save_baselines(self) -> None:
        self._baseline_path.parent.mkdir(parents=True, exist_ok=True)
        self._baseline_path.write_text(
            json.dumps(dict(sorted(self._baselines.items())), indent=2),
            encoding="utf-8",
        )

    # -- write ---------------------------------------------------------------

    def write(
        self, actor: str, key: str, value: str, *, session_id: str = "default",
    ) -> MemoryResult:
        target = f"memory:{key}"

        if len(value.encode("utf-8")) > self._max_bytes:
            return self._deny_write(actor, target, Decision.block(
                BlockReason.MEMORY_SIZE_EXCEEDED,
                [finding("memory_guard", "memory.size_anomaly", "high", owasp="ASI06")],
            ), session=session_id)

        if self.is_protected(key) and actor not in self._trusted:
            return self._deny_write(actor, target, Decision.block(
                BlockReason.MEMORY_KEY_PROTECTED,
                [finding("memory_guard", "memory.protected_key_write", "high",
                         owasp="ASI06")],
            ), session=session_id)

        result = self._gate.scan_text(value, ScanContext(
            actor=actor, direction="outbound", target=target))
        if result.blocked:
            self._quarantine(key, value, result.block_reason or "", actor)
            self._taint.mark(session_id, TaintSource.MEMORY_POISON)
            return self._deny_write(actor, target, Decision.block(
                BlockReason.MEMORY_POISON_BLOCKED,
                [finding("memory_guard", "memory.poison_write", "critical",
                         owasp="ASI06", mitre="T1565")] + result.findings,
            ), session=session_id)

        if result.verdict == "ask":
            # No HITL path for a memory write — fail closed (not quarantined:
            # an ask is unconfirmed, the payload never landed).
            return self._deny_write(actor, target, Decision.block(
                result.block_reason or BlockReason.APPROVAL_REQUIRED,
                result.findings), session=session_id)

        stored = result.text if result.verdict == "strip" else value
        entry = self._store.put(key, stored, actor, utcnow_iso())
        if self.is_protected(key):
            self._baselines[key] = entry.sha256
            self._save_baselines()
        self._record(actor=actor, action="memory_write", target=target,
                     verdict=result.verdict, findings=result.findings,
                     redaction=result.redaction or None, session=session_id)
        return MemoryResult(decision=Decision.allow(), redaction=result.redaction)

    # -- read ----------------------------------------------------------------

    def read(
        self, actor: str, key: str, *, session_id: str = "default",
    ) -> MemoryResult:
        target = f"memory:{key}"
        entry = self._store.get(key)
        if entry is None:
            self._record(actor=actor, action="memory_read", target=target, verdict="allow")
            return MemoryResult(decision=Decision.allow(), value=None)

        # Integrity first: a protected key whose current value no longer
        # matches its baseline was modified out-of-band. Always enforced.
        if self.is_protected(key):
            baseline = self._baselines.get(key)
            if baseline is not None and value_hash(entry.value) != baseline:
                self._quarantine(key, entry.value,
                                 BlockReason.PROTECTED_KEY_TAMPERED, actor)
                self._store.delete(key)
                self._taint.mark(session_id, TaintSource.MEMORY_POISON)
                decision = Decision.block(
                    BlockReason.PROTECTED_KEY_TAMPERED,
                    [finding("memory_guard", "memory.protected_key_tamper",
                             "critical", owasp="ASI06", mitre="T1565")],
                )
                self._record(actor=actor, action="memory_read", target=target,
                             verdict="block", block_reason=decision.block_reason,
                             findings=decision.findings, session=session_id)
                return MemoryResult(decision=decision)

        result = self._gate.scan_text(entry.value, ScanContext(
            actor=actor, direction="inbound", target=target))
        if result.blocked:
            self._quarantine(key, entry.value, result.block_reason or "", actor)
            self._store.delete(key)
            self._baselines.pop(key, None)
            self._save_baselines()
            self._taint.mark(session_id, TaintSource.MEMORY_POISON)
            decision = Decision.block(
                BlockReason.MEMORY_POISON_BLOCKED,
                [finding("memory_guard", "memory.poison_read", "critical",
                         owasp="ASI06", mitre="T1565")] + result.findings,
            )
            self._record(actor=actor, action="memory_read", target=target,
                         verdict="block", block_reason=decision.block_reason,
                         findings=decision.findings, session=session_id)
            return MemoryResult(decision=decision)

        if result.verdict == "ask":
            decision = Decision.block(
                result.block_reason or BlockReason.APPROVAL_REQUIRED,
                result.findings)
            self._record(actor=actor, action="memory_read", target=target,
                         verdict="block", block_reason=decision.block_reason,
                         findings=decision.findings, session=session_id)
            return MemoryResult(decision=decision)

        self._record(actor=actor, action="memory_read", target=target,
                     verdict=result.verdict, findings=result.findings,
                     redaction=result.redaction or None, session=session_id)
        return MemoryResult(decision=Decision.allow(), value=result.text,
                            redaction=result.redaction)

    # -- integrity sweep -----------------------------------------------------

    def verify(self, actor: str) -> list[str]:
        """Check every protected key against its baseline; returns tampered
        keys. Read-only (no quarantine) — the diagnostic behind ``al memory
        verify``; one receipt covers the sweep."""
        tampered = [
            key for key, baseline in self._baselines.items()
            if (entry := self._store.get(key)) is not None
            and value_hash(entry.value) != baseline
        ]
        self._record(
            actor=actor, action="memory_read", target="memory:verify",
            verdict="block" if tampered else "allow",
            block_reason=BlockReason.PROTECTED_KEY_TAMPERED if tampered else None,
            findings=[finding("memory_guard", "memory.protected_key_tamper",
                              "critical", owasp="ASI06", mitre="T1565")
                      for _ in tampered],
        )
        return tampered

    # -- snapshot + rollback ---------------------------------------------------

    def snapshot(self, actor: str) -> SnapshotInfo:
        """Capture store + baselines as known-good."""
        self._snapshot_dir.mkdir(parents=True, exist_ok=True)
        snapshot_id = f"snap-{len(list(self._snapshot_dir.glob('snap-*.json'))) + 1:04d}"
        path = self._snapshot_dir / f"{snapshot_id}.json"
        entries = self._store.entries()
        path.write_text(json.dumps({
            "snapshot_id": snapshot_id,
            "ts": utcnow_iso(),
            "store_hash": self._store.store_hash(),
            "entries": {k: e.__dict__ for k, e in sorted(entries.items())},
            "baselines": dict(sorted(self._baselines.items())),
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        self._record(actor=actor, action="memory_write",
                     target=f"memory:snapshot:{snapshot_id}", verdict="allow")
        return SnapshotInfo(snapshot_id=snapshot_id, path=path,
                            store_hash=self._store.store_hash(),
                            keys=sorted(entries))

    def rollback(self, actor: str, snapshot_id: str | None = None) -> RollbackInfo:
        """Restore the named (default: latest) snapshot. Raises if none exist."""
        snapshots = sorted(self._snapshot_dir.glob("snap-*.json"))
        if snapshot_id is not None:
            snapshots = [p for p in snapshots if p.stem == snapshot_id]
        if not snapshots:
            raise FileNotFoundError(
                f"no snapshot {snapshot_id or ''} in {self._snapshot_dir} — "
                "take one with snapshot() first")
        data = json.loads(snapshots[-1].read_text(encoding="utf-8"))
        before = self._store.store_hash()
        self._store.replace_all(
            {k: MemoryEntry(**v) for k, v in data["entries"].items()})
        self._baselines = dict(data["baselines"])
        self._save_baselines()
        after = self._store.store_hash()
        self._record(actor=actor, action="memory_write",
                     target=f"memory:rollback:{data['snapshot_id']}", verdict="allow")
        return RollbackInfo(snapshot_id=data["snapshot_id"], before_hash=before,
                            after_hash=after, restored_keys=sorted(data["entries"]))

    # -- quarantine ------------------------------------------------------------

    def quarantined(self) -> list[dict[str, Any]]:
        if not self._quarantine_path.exists():
            return []
        return json.loads(self._quarantine_path.read_text(encoding="utf-8"))

    def _quarantine(self, key: str, value: str, reason: str, actor: str) -> None:
        """Preserve a hostile payload for forensics, outside the active store.
        The quarantine file holds the plaintext; receipts never do."""
        items = self.quarantined()
        items.append({
            "id": f"q-{len(items) + 1:04d}",
            "key": key,
            "sha256": value_hash(value),
            "reason": reason,
            "actor": actor,
            "ts": utcnow_iso(),
            "value": value,
        })
        self._quarantine_path.parent.mkdir(parents=True, exist_ok=True)
        self._quarantine_path.write_text(
            json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")

    def _deny_write(self, actor: str, target: str, decision: Decision,
                    *, session: str | None = None) -> MemoryResult:
        self._record(actor=actor, action="memory_write", target=target,
                     verdict="block", block_reason=decision.block_reason,
                     findings=decision.findings, session=session)
        return MemoryResult(decision=decision)


__all__ = ["MemoryGuard", "MemoryResult", "RollbackInfo", "SnapshotInfo"]
