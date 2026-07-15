"""Evidence pool — one query surface over several planes' ledgers.

The compose topology gives every plane its **own** ledger with its own single
writer (invariant #7): the gateway (data plane) writes the receipts operators
actually care about, the control plane writes only its own actions (kill
switch, config). The dashboard lives on the control plane, so without help it
would show the control ledger and nothing else — which is exactly the bug an
operator reports as "my traffic never shows up".

The pool fixes that read-side only. Each extra plane is attached as a
:class:`RemotePlane`: a **read-only** SQLite connection over that plane's live
mirror (shared volume) plus its public key and canonical JSONL for chain
verification. Nothing here can write another plane's chain or mirror — the
one-writer invariant holds by construction, not by discipline.

Every receipt returned by the pool is tagged with a ``plane`` key (presentation
only — the tag is added after the signed body is loaded, so signatures still
verify over the original fields).
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Any

from al_verify.verify import load_public_key, verify_chain

from . import JsonlLedger
from .db import SqliteMirror

log = logging.getLogger("al.audit.pool")


def _tag(receipt: dict[str, Any], plane: str) -> dict[str, Any]:
    receipt["plane"] = plane
    return receipt


class RemotePlane:
    """Another process's evidence, opened read-only over a shared volume.

    The mirror may not exist yet (the writer has not booted) or may be replaced
    (volume recreated) — every access re-opens on failure and degrades to
    "no events" rather than taking the dashboard down with it.
    """

    def __init__(self, plane: str, data_dir: str | Path,
                 pubkey_path: str | Path | None = None) -> None:
        self.plane = plane
        self.data_dir = Path(data_dir)
        self.db_path = self.data_dir / "al.sqlite"
        self.jsonl_path = self.data_dir / "ledger.jsonl"
        self.pubkey_path = (Path(pubkey_path) if pubkey_path is not None
                            else self.data_dir / "keys" / "mediator_ed25519.pub")
        self._mirror: SqliteMirror | None = None

    def mirror(self) -> SqliteMirror | None:
        if self._mirror is None:
            try:
                self._mirror = SqliteMirror(self.db_path, read_only=True)
            except sqlite3.Error as exc:
                log.debug("plane %r mirror not readable yet: %s", self.plane, exc)
                return None
        return self._mirror

    def query(self, method: str, /, *args: Any, **kwargs: Any) -> Any:
        """Run one mirror query; on error drop the connection and report empty.

        A vanished/recreated database must degrade to "no events from this
        plane", never to a dashboard 500."""
        mirror = self.mirror()
        if mirror is None:
            return None
        try:
            return getattr(mirror, method)(*args, **kwargs)
        except sqlite3.Error as exc:
            log.warning("plane %r query %s failed (%s) — reopening next call",
                        self.plane, method, exc)
            try:
                mirror.close()
            except Exception:  # noqa: BLE001 — already broken
                pass
            self._mirror = None
            return None

    def public_key(self):  # noqa: ANN201 — Ed25519PublicKey
        return load_public_key(self.pubkey_path.read_bytes())

    def chain_status(self) -> dict[str, Any]:
        """Standalone chain verification of this plane's canonical JSONL.

        Fail-closed either way: whatever we cannot check is never reported as
        verified. But *why* it is unverified matters. A chain whose signatures
        do not check out means tampering — the loudest alarm this product has.
        A pubkey we cannot read (never pointed at the native ``keys/`` dir, or
        the plane has not booted) means we could not look. Reporting the second
        as the first would make that alarm cry wolf on a config typo, and an
        operator who sees one false BROKEN stops believing the real one.
        ``reason`` keeps them apart: ``unavailable`` = could not check,
        ``invalid`` = checked and it failed.
        """
        try:
            records = JsonlLedger(self.jsonl_path).read_all()
        except OSError as exc:
            return self._unverified("unavailable", f"ledger unreadable: {exc}")
        if not records:  # plane not booted yet — nothing to verify
            return {"verified": True, "length": 0, "reason": None, "error": None}
        try:
            key = self.public_key()
        except Exception as exc:  # noqa: BLE001 — missing/malformed key = cannot check
            return self._unverified(
                "unavailable",
                f"no usable public key at {self.pubkey_path}: {exc}")
        try:
            length = verify_chain(records, key)
        except Exception as exc:  # noqa: BLE001 — the check ran and it failed
            return self._unverified("invalid", str(exc))
        return {"verified": True, "length": length, "reason": None, "error": None}

    @staticmethod
    def _unverified(reason: str, error: str) -> dict[str, Any]:
        return {"verified": False, "length": 0, "reason": reason, "error": error}

    def close(self) -> None:
        if self._mirror is not None:
            self._mirror.close()
            self._mirror = None


class EvidencePool:
    """Merged, org-scoped, plane-tagged reads over the local ledger plus any
    attached remote planes. The local plane stays first — ties in merged
    ordering resolve toward it deterministically."""

    def __init__(self, local_plane: str, local_db: Any,
                 remotes: list[RemotePlane] | None = None) -> None:
        self.local_plane = local_plane
        self._local = local_db
        self._remotes = remotes or []

    @property
    def planes(self) -> list[str]:
        return [self.local_plane, *(r.plane for r in self._remotes)]

    def _each(self, method: str, /, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """{plane: result} for one query across all planes (None on failure)."""
        out = {self.local_plane: getattr(self._local, method)(*args, **kwargs)}
        for remote in self._remotes:
            out[remote.plane] = remote.query(method, *args, **kwargs)
        return out

    # -- merged reads --------------------------------------------------------

    def _merged_receipts(self, method: str, /, *, limit: int,
                         **filters: Any) -> list[dict[str, Any]]:
        merged: list[dict[str, Any]] = []
        for plane, receipts in self._each(method, limit=limit, **filters).items():
            merged.extend(_tag(r, plane) for r in receipts or [])
        # Newest first; ts strings are RFC 3339 (lexicographically ordered).
        # plane/seq tiebreak keeps the order stable across polls.
        merged.sort(key=lambda r: (r.get("ts", ""), r.get("plane", ""),
                                   r.get("seq", 0)), reverse=True)
        return merged[:limit]

    def recent_filtered(self, *, limit: int = 50, **filters: Any) -> list[dict[str, Any]]:
        return self._merged_receipts("recent_filtered", limit=limit, **filters)

    def search(self, *, limit: int = 100, **filters: Any) -> list[dict[str, Any]]:
        return self._merged_receipts("search", limit=limit, **filters)

    def stats(self, org: str | None = None) -> dict[str, Any]:
        """Merged one-shot summary; per-plane event counts under ``planes``."""
        def merge_counts(dsts: dict[str, int], src: dict[str, int] | None) -> None:
            for k, v in (src or {}).items():
                dsts[k] = dsts.get(k, 0) + v

        events = 0
        planes: dict[str, int] = {}
        merged: dict[str, dict[str, int]] = {
            "verdicts": {}, "actions": {}, "block_reasons": {},
            "actors": {}, "orgs": {},
        }
        for plane, stats in self._each("stats", org).items():
            if stats is None:
                planes[plane] = 0
                continue
            events += stats.get("events", 0)
            planes[plane] = stats.get("events", 0)
            for key, dst in merged.items():
                merge_counts(dst, stats.get(key))
        return {"events": events, "planes": planes, **merged}

    def org_counts(self, org: str | None = None) -> dict[str, int]:
        out: dict[str, int] = {}
        for counts in self._each("org_counts", org).values():
            for k, v in (counts or {}).items():
                out[k] = out.get(k, 0) + v
        return out

    def time_series(self, *, buckets: int = 24, span_hours: int = 24,
                    org: str | None = None) -> list[dict[str, Any]]:
        """Bucket-aligned sum across planes (one shared ``now`` anchors both)."""
        latest = [r[0]["ts"] for r in
                  self._each("recent_filtered", limit=1, org=org).values() if r]
        if not latest:
            return []
        now = max(latest)
        merged: list[dict[str, Any]] | None = None
        for series in self._each("time_series", buckets=buckets,
                                 span_hours=span_hours, now=now, org=org).values():
            if not series:
                continue
            if merged is None:
                merged = [dict(b) for b in series]
                continue
            for dst, src in zip(merged, series):
                for key, val in src.items():
                    if isinstance(val, int):
                        dst[key] = dst.get(key, 0) + val
        return merged or []

    def receipt_by_seq(self, seq: int, org: str | None = None,
                       plane: str | None = None) -> dict[str, Any] | None:
        """One receipt by (plane, seq). ``plane=None`` = the local plane, so a
        single-ledger deployment keeps its old URL shape."""
        plane = plane or self.local_plane
        if plane == self.local_plane:
            receipt = self._local.receipt_by_seq(seq, org)
        else:
            remote = self._remote(plane)
            receipt = remote.query("receipt_by_seq", seq, org) if remote else None
        return _tag(receipt, plane) if receipt else None

    def public_key_for(self, plane: str | None, local_key):  # noqa: ANN201
        plane = plane or self.local_plane
        if plane == self.local_plane:
            return local_key
        remote = self._remote(plane)
        if remote is None:
            raise KeyError(f"unknown plane: {plane!r}")
        return remote.public_key()

    def chains(self, local_chain: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """Per-plane chain verification status ({plane: healthz-shaped dict})."""
        out = {self.local_plane: local_chain}
        for remote in self._remotes:
            out[remote.plane] = remote.chain_status()
        return out

    def _remote(self, plane: str) -> RemotePlane | None:
        return next((r for r in self._remotes if r.plane == plane), None)

    def close(self) -> None:
        for remote in self._remotes:
            remote.close()


__all__ = ["EvidencePool", "RemotePlane"]
