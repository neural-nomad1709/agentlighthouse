"""Receipt v1 — build, sign, and chain mediator-signed evidence.

Every AgentLighthouse decision emits a receipt. The signing/hashing procedure is
defined once, in ``al_verify.verify``; this module reuses those functions so the
producing side and any independent verifier are provably symmetric.

Design choices that keep canonicalization unambiguous (see al_verify.canonical):
  * numeric fields are integers (``seq``, redaction counts); timestamps are strings;
  * ``findings`` is a list of objects; ``redaction`` is class -> integer count
    (never plaintext — invariant, no secret ever enters a receipt).
"""

from __future__ import annotations

import base64
import datetime as _dt
from typing import Any, Literal, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field

from al_verify.verify import (
    GENESIS_PREV_HASH,
    SIG_PREFIX,
    compute_record_hash,
    signing_input,
)

RECEIPT_VERSION = 1

# Action vocabulary — the closed set of mediated operations (see spec/receipt-v1.md).
Action = Literal[
    "http_forward",
    "fetch",
    "llm_call",
    "mcp_tool_call",
    "mcp_tool_result",
    "memory_read",
    "memory_write",
    "skill_load",
    "a2a_message",
    "config_change",
    "killswitch",
]
ACTIONS: tuple[str, ...] = tuple(Action.__args__)  # type: ignore[attr-defined]

# Verdict vocabulary, in precedence order (block wins, allow loses).
Verdict = Literal["block", "strip", "warn", "ask", "allow"]
VERDICTS: tuple[str, ...] = tuple(Verdict.__args__)  # type: ignore[attr-defined]
VERDICT_PRECEDENCE = {v: i for i, v in enumerate(VERDICTS)}  # lower index == stronger


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scanner: str
    rule_id: str
    severity: Literal["low", "medium", "high", "critical"]
    owasp: str | None = None
    mitre: str | None = None


class Receipt(BaseModel):
    """Validated receipt (schema v1). Serialized to a plain dict for signing."""

    model_config = ConfigDict(extra="forbid")

    v: int = RECEIPT_VERSION
    seq: int
    ts: str
    actor: str
    action: Action
    target: str
    verdict: Verdict
    findings: list[Finding] = Field(default_factory=list)
    block_reason: str | None = None
    policy_hash: str | None = None
    redaction: dict[str, int] | None = None
    session: str | None = None
    latency_ms: int | None = Field(default=None, ge=0)
    prev_hash: str
    record_hash: str | None = None
    sig: str | None = None

    def unsigned_dict(self) -> dict[str, Any]:
        """Dict with all present fields except record_hash and sig (drops None)."""
        data = self.model_dump(exclude_none=True)
        data.pop("record_hash", None)
        data.pop("sig", None)
        return data


def utcnow_iso() -> str:
    """RFC 3339 UTC timestamp with millisecond precision and a trailing 'Z'."""
    now = _dt.datetime.now(_dt.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def sign_receipt(unsigned: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    """Attach ``record_hash`` then ``sig`` to an unsigned receipt dict."""
    receipt = {k: v for k, v in unsigned.items() if k not in ("record_hash", "sig")}
    receipt["record_hash"] = compute_record_hash(receipt)
    signature = private_key.sign(signing_input(receipt))
    receipt["sig"] = SIG_PREFIX + base64.b64encode(signature).decode("ascii")
    return receipt


class ReceiptSigner:
    """Stateful signer that maintains the hash chain (seq + prev_hash).

    Not concurrency-safe on its own; the caller serializes appends (the audit
    log is the single writer). ``start_seq``/``prev_hash`` let the chain resume
    from a persisted ledger tail.
    """

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        *,
        start_seq: int = 0,
        prev_hash: str = GENESIS_PREV_HASH,
    ) -> None:
        self._key = private_key
        self._seq = start_seq
        self._prev = prev_hash

    @property
    def next_seq(self) -> int:
        return self._seq

    @property
    def prev_hash(self) -> str:
        return self._prev

    def record(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        verdict: str,
        findings: Sequence[dict[str, Any]] | None = None,
        block_reason: str | None = None,
        policy_hash: str | None = None,
        redaction: dict[str, int] | None = None,
        session: str | None = None,
        latency_ms: int | None = None,
        ts: str | None = None,
    ) -> dict[str, Any]:
        """Build, validate, sign, and chain one receipt; advance chain state."""
        model = Receipt(
            seq=self._seq,
            ts=ts or utcnow_iso(),
            actor=actor,
            action=action,  # type: ignore[arg-type]
            target=target,
            verdict=verdict,  # type: ignore[arg-type]
            findings=[Finding(**f) for f in (findings or [])],
            block_reason=block_reason,
            policy_hash=policy_hash,
            redaction=redaction,
            session=session,
            latency_ms=latency_ms,
            prev_hash=self._prev,
        )
        signed = sign_receipt(model.unsigned_dict(), self._key)
        self._prev = signed["record_hash"]
        self._seq += 1
        return signed


__all__ = [
    "ACTIONS",
    "VERDICTS",
    "VERDICT_PRECEDENCE",
    "RECEIPT_VERSION",
    "Finding",
    "Receipt",
    "ReceiptSigner",
    "sign_receipt",
    "utcnow_iso",
]
