"""Signed per-org posture attestation.

The artefact a design partner's auditor actually wants: a single signed
statement of what this org's mediator *was configured to do* and what it
*actually did* over a period — tied to the receipt chain it was cut from, and
verifiable with the standalone ``al-verify`` (no al-core, no governance).

It is deliberately not a summary you could fabricate: every count is derived
from the ledger, the chain head is quoted, and the whole document is signed
with the mediator key. If the ledger were edited afterwards, the chain would
fail to verify and the attestation's quoted head would no longer match.

**Evidence level** (an honest, computed ladder — never asserted):

* ``AEL-0`` — self-reported; the chain does not verify. Nothing here is trusted.
* ``AEL-1`` — every decision is signed and the chain verifies from genesis.
* ``AEL-2`` — AEL-1 **and** the plane enforces (mode is not ``audit``): the
  receipts describe blocks that actually happened, not observations.
* ``AEL-3`` — AEL-2 **and** the choke-point is self-proving in production: the
  L0 egress bypass self-test is enforced, so the mediator refuses to run in a
  deployment it could be routed around.

A level is only ever *reduced* by a failing condition, so a misconfigured
deployment cannot claim a level it has not earned.
"""

from __future__ import annotations

from typing import Any

from al_core.egress import self_test_enabled
from al_core.keys import public_key_hex
from al_core.receipt import sign_receipt, utcnow_iso
from al_core.runtime import Runtime
from al_verify.verify import ATTESTATION_KIND

#: OWASP ASI risks we report coverage for (findings carry the tag).
_ASI_KEYS = [f"ASI{i:02d}" for i in range(1, 11)]


def evidence_level(*, chain_verified: bool, enforcing: bool, self_test: bool) -> str:
    if not chain_verified:
        return "AEL-0"
    if not enforcing:
        return "AEL-1"
    if not self_test:
        return "AEL-2"
    return "AEL-3"


def build_attestation(
    runtime: Runtime, org: str, *, since: str | None = None, until: str | None = None,
) -> dict[str, Any]:
    """Build and sign an org's posture attestation from the ledger + config."""
    db = runtime.ledger.db
    settings = runtime.settings
    health = runtime.healthz()
    chain = health["chain"]

    receipts = db.search(org=org, since=since, until=until, limit=500)
    by_verdict: dict[str, int] = {}
    by_action: dict[str, int] = {}
    by_reason: dict[str, int] = {}
    asi: dict[str, int] = {}
    for r in receipts:
        by_verdict[r["verdict"]] = by_verdict.get(r["verdict"], 0) + 1
        by_action[r["action"]] = by_action.get(r["action"], 0) + 1
        if r.get("block_reason"):
            by_reason[r["block_reason"]] = by_reason.get(r["block_reason"], 0) + 1
        for f in r.get("findings") or []:
            tag = f.get("owasp")
            if tag in _ASI_KEYS:
                asi[tag] = asi.get(tag, 0) + 1

    enforcing = settings.mode != "audit"
    self_test = self_test_enabled(settings.egress, settings.env)
    level = evidence_level(chain_verified=chain["verified"], enforcing=enforcing,
                           self_test=self_test)

    doc: dict[str, Any] = {
        "kind": ATTESTATION_KIND,
        "org": org,
        "issued_ts": utcnow_iso(),
        "period": {"since": since, "until": until},
        "posture": {
            "mode": settings.mode,
            "env": settings.env,
            "enforcing": enforcing,
            "egress_self_test": self_test,
            "config_hash": runtime.config_hash,
            "killswitch_engaged": runtime.killswitch.engaged(),
        },
        "evidence": {
            "events": len(receipts),
            "blocks": by_verdict.get("block", 0),
            "by_verdict": dict(sorted(by_verdict.items())),
            "by_action": dict(sorted(by_action.items())),
            "by_block_reason": dict(sorted(by_reason.items())),
            "asi_findings": dict(sorted(asi.items())),
        },
        "chain": {
            "verified": chain["verified"],
            "length": chain["length"],
            "head": _chain_head(runtime),
        },
        "evidence_level": level,
        "mediator_public_key": public_key_hex(runtime.public_key),
    }
    # Drop the period when unbounded so the canonical form stays minimal.
    if since is None and until is None:
        doc.pop("period")
    return sign_receipt(doc, runtime.signing_key)


def _chain_head(runtime: Runtime) -> str | None:
    """The record_hash of the ledger's newest receipt — what this attestation
    was cut from. Unscoped by design: the chain is one chain, and quoting its
    head is what lets an auditor tie the attestation back to the ledger."""
    latest = runtime.ledger.db.latest_seq()
    if latest is None:
        return None
    receipt = runtime.ledger.db.receipt_by_seq(latest)
    return receipt.get("record_hash") if receipt else None


__all__ = ["ATTESTATION_KIND", "build_attestation", "evidence_level"]
