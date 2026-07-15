"""Rule miner — turn what the plane blocked into what it should block next.

**The honest constraint that shapes this module:** receipts deliberately carry
no plaintext (invariant: no secret, no payload, ever enters the evidence
ledger). So a miner cannot read attack strings out of the ledger, and any
design that claims to is lying about where its data came from. There are
exactly two truthful sources:

* **the ledger** — repeated *targets* (a host, a tool) that keep getting
  blocked. Targets are already in the receipt: they are the thing acted upon,
  not the content. A host that tripped an exfil block five times is a
  candidate deny rule.
* **the quarantine** — the memory guard preserves hostile payloads in a
  separate file precisely so a human can look at them. That file has the real
  text, so patterns mined from it are real patterns.

Everything mined is a **candidate**: unapproved, unsigned, inert. Nothing here
changes a verdict. The review gate (``bundle.py``) is what turns a candidate
into a rule, and only a human can pull that lever.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit


@dataclass
class Candidate:
    """A proposed rule. Inert until a human approves and signs it."""

    rule_id: str
    pattern: str                      # regex, matched against scanned text
    action: str = "block"
    severity: str = "high"
    owasp: str | None = None
    mitre: str | None = None
    rationale: str = ""
    hits: int = 1                     # how many blocks support it
    source_seqs: list[int] = field(default_factory=list)
    sample: str = ""                  # a string the rule must match (regression test)

    def to_rule(self) -> dict[str, Any]:
        rule: dict[str, Any] = {
            "rule_id": self.rule_id,
            "pattern": self.pattern,
            "action": self.action,
            "severity": self.severity,
            "sample": self.sample,
        }
        if self.owasp:
            rule["owasp"] = self.owasp
        if self.mitre:
            rule["mitre"] = self.mitre
        return rule


def _host_of(target: str) -> str | None:
    parts = urlsplit(target if "//" in target else f"//{target}")
    return parts.hostname


def mine(
    receipts: Iterable[dict[str, Any]],
    quarantine: Iterable[dict[str, Any]] = (),
    *,
    min_hits: int = 2,
) -> list[Candidate]:
    """Propose rules from blocked receipts + quarantined payloads.

    ``min_hits`` is the noise floor: one block is an incident, several is a
    pattern. A rule proposed from a single event would mostly encode the
    coincidence of that event.
    """
    receipts = [r for r in receipts if r.get("verdict") == "block"]
    candidates: list[Candidate] = []

    # 1. Hosts that keep getting blocked (ledger; targets, never content).
    host_hits: Counter[str] = Counter()
    host_seqs: dict[str, list[int]] = {}
    host_tags: dict[str, tuple[str | None, str | None]] = {}
    for r in receipts:
        if r.get("action") not in ("fetch", "http_forward", "llm_call"):
            continue
        host = _host_of(r.get("target", ""))
        if not host:
            continue
        host_hits[host] += 1
        host_seqs.setdefault(host, []).append(int(r["seq"]))
        f = (r.get("findings") or [{}])[0]
        host_tags[host] = (f.get("owasp"), f.get("mitre"))

    for host, hits in host_hits.items():
        if hits < min_hits:
            continue
        owasp, mitre = host_tags.get(host, (None, None))
        candidates.append(Candidate(
            rule_id=f"learned.host.{re.sub(r'[^a-z0-9]+', '_', host.lower())}",
            pattern=re.escape(host),
            owasp=owasp or "ASI08", mitre=mitre,
            rationale=f"{host} was blocked {hits} times",
            hits=hits, source_seqs=sorted(host_seqs[host]), sample=host,
        ))

    # 2. Payload patterns (quarantine; the one place real text legitimately is).
    phrase_hits: Counter[str] = Counter()
    phrase_sample: dict[str, str] = {}
    for item in quarantine:
        value = item.get("value", "")
        for phrase in _phrases(value):
            phrase_hits[phrase] += 1
            phrase_sample.setdefault(phrase, value[:200])

    for phrase, hits in phrase_hits.items():
        if hits < min_hits:
            continue
        candidates.append(Candidate(
            rule_id=f"learned.phrase.{re.sub(r'[^a-z0-9]+', '_', phrase[:32])}",
            pattern=re.escape(phrase),
            owasp="ASI01", mitre="T1204",
            rationale=f"quarantined payloads shared the phrase {phrase!r} ({hits}x)",
            hits=hits, sample=phrase_sample[phrase],
        ))

    return sorted(candidates, key=lambda c: -c.hits)


_URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.I)


def _phrases(text: str) -> set[str]:
    """Signals worth generalizing from a quarantined payload.

    Deliberately narrow: exfil endpoints (a URL in hostile content is where the
    data was going) and the imperative openers injections reuse. A miner that
    proposed every 5-gram would bury the reviewer, and a rule nobody reads is a
    rule nobody can refuse."""
    out: set[str] = set()
    for url in _URL_RE.findall(text):
        host = _host_of(url)
        if host:
            out.add(host)
    lowered = text.lower()
    for opener in ("ignore all previous instructions",
                   "ignore your instructions",
                   "disregard the above",
                   "forward every user message"):
        if opener in lowered:
            out.add(opener)
    return out


__all__ = ["Candidate", "mine"]
