"""SIEM export — receipts as flat, MITRE-tagged events (L6).

A receipt is evidence: canonical, signed, chained. A SIEM event is a *query
surface*: flat, denormalized, tagged with the ATT&CK techniques and OWASP ASI
risks the findings cite, so a SOC can pivot on `threat.technique.id` without
knowing anything about AgentLighthouse.

The mapping is lossless in the direction that matters — every exported event
carries `record_hash`, `prev_hash`, and `sig`, so an analyst who sees an alert
can pull the original receipt and verify it with `al-verify`. Fields follow
Elastic Common Schema names where an obvious one exists (`@timestamp`,
`event.*`, `user.*`, `threat.*`); the rest live under `al.*`. Nothing is
invented: the event says only what the receipt said, never plaintext.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, TextIO

#: Verdict -> ECS event.outcome + a severity floor a SIEM can alert on.
_OUTCOME = {
    "block": ("failure", "high"),
    "strip": ("success", "medium"),
    "warn": ("success", "low"),
    "ask": ("unknown", "medium"),
    "allow": ("success", "low"),
}

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def to_event(receipt: dict[str, Any]) -> dict[str, Any]:
    """One receipt -> one flat SIEM event (ECS-shaped, MITRE-tagged)."""
    findings = receipt.get("findings") or []
    verdict = receipt.get("verdict", "allow")
    outcome, floor = _OUTCOME.get(verdict, ("unknown", "medium"))

    # Severity = the strongest finding, floored by the verdict's own weight.
    severity = max(
        (f.get("severity", "low") for f in findings),
        key=lambda s: _SEVERITY_RANK.get(s, 0),
        default=floor,
    )
    if _SEVERITY_RANK.get(severity, 0) < _SEVERITY_RANK[floor]:
        severity = floor

    techniques = sorted({f["mitre"] for f in findings if f.get("mitre")})
    owasp = sorted({f["owasp"] for f in findings if f.get("owasp")})

    event: dict[str, Any] = {
        "@timestamp": receipt.get("ts"),
        "event": {
            "kind": "alert" if verdict == "block" else "event",
            "category": ["intrusion_detection"],
            "action": receipt.get("action"),
            "outcome": outcome,
            "severity": severity,
            "provider": "agentlighthouse",
            "sequence": receipt.get("seq"),
        },
        "user": {"id": receipt.get("actor")},
        "al": {
            "verdict": verdict,
            "target": receipt.get("target"),
            "block_reason": receipt.get("block_reason"),
            "policy_hash": receipt.get("policy_hash"),
            "redaction": receipt.get("redaction"),
            "session": receipt.get("session"),
            "latency_ms": receipt.get("latency_ms"),
            "rules": [f"{f.get('scanner')}/{f.get('rule_id')}" for f in findings],
            "owasp": owasp,
            # The pointers that make the alert verifiable, not just readable.
            "record_hash": receipt.get("record_hash"),
            "prev_hash": receipt.get("prev_hash"),
            "sig": receipt.get("sig"),
        },
    }
    if techniques:
        event["threat"] = {
            "framework": "MITRE ATT&CK",
            "technique": {"id": techniques},
        }
    return {k: v for k, v in event.items() if v is not None}


def export(receipts: Iterable[dict[str, Any]], out: TextIO) -> int:
    """Write receipts as newline-delimited SIEM events. Returns the count."""
    n = 0
    for receipt in receipts:
        out.write(json.dumps(to_event(receipt), ensure_ascii=False,
                             separators=(",", ":")) + "\n")
        n += 1
    return n


__all__ = ["export", "to_event"]
