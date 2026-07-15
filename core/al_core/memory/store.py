"""L5 memory substrate — a deliberately dumb, file-backed key-value store.

The store holds agent memory (scratchpad entries, notes, retrieval snippets)
as JSON on disk: one entry per key with the value, its SHA-256, who wrote it,
and when. **All screening, integrity checking, and policy live in
``MemoryGuard``** — nothing legitimate writes this file except the guard. An
attacker editing it directly is exactly the out-of-band tamper the guard's
integrity baselines detect, because the baselines live in a *separate*
mediator-owned file.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path


def value_hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class MemoryEntry:
    value: str
    sha256: str
    actor: str
    ts: str


class MemoryStore:
    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._entries: dict[str, MemoryEntry] = {}
        if self._path.exists():
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            self._entries = {k: MemoryEntry(**v) for k, v in raw.items()}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps({k: asdict(e) for k, e in sorted(self._entries.items())},
                       indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def get(self, key: str) -> MemoryEntry | None:
        return self._entries.get(key)

    def put(self, key: str, value: str, actor: str, ts: str) -> MemoryEntry:
        entry = MemoryEntry(value=value, sha256=value_hash(value), actor=actor, ts=ts)
        self._entries[key] = entry
        self._save()
        return entry

    def delete(self, key: str) -> None:
        if self._entries.pop(key, None) is not None:
            self._save()

    def keys(self) -> list[str]:
        return sorted(self._entries)

    def entries(self) -> dict[str, MemoryEntry]:
        return dict(self._entries)

    def replace_all(self, entries: dict[str, MemoryEntry]) -> None:
        """Atomically swap the whole store (rollback restores a snapshot)."""
        self._entries = dict(entries)
        self._save()

    def store_hash(self) -> str:
        """One hash over the whole store — the before/after evidence a rollback
        shows (canonical: sorted keys, entry hashes only, no timestamps)."""
        blob = json.dumps({k: e.sha256 for k, e in sorted(self._entries.items())},
                          separators=(",", ":"))
        return value_hash(blob)


__all__ = ["MemoryEntry", "MemoryStore", "value_hash"]
