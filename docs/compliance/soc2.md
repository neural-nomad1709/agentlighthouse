# SOC 2 mapping (Trust Services Criteria) — planning aid

For an organization whose SOC 2 scope includes agentic AI workloads: which
criteria AgentLighthouse mechanisms support, and what an auditor can pull as
evidence. The plane does not make an organization SOC 2 compliant — it
supplies controls and, unusually, **independently verifiable** evidence for
them. Planning aid, not an audit opinion.

## Common Criteria

| Criteria | Mechanism | Auditor evidence |
|----------|-----------|------------------|
| CC6.1 Logical access — identification, authorization | SPIFFE-style agent identities (no identity -> deny); per-user virtual keys and governance tokens hashed at rest, shown once; default-deny tool policy per identity | issuance records (`al vkey list` — hashes only); `NO_IDENTITY` denial receipts |
| CC6.3 Access modification and removal | Immediate revocation (`al vkey revoke`, `al-gov user revoke`); explicit-deny-wins policy edits land with signed config-change records | revocation receipts; policy file history |
| CC6.6 External access boundaries | Agents on an internal network whose only egress is the mediation choke-point; control plane unreachable from agents; both properties proven live by one-shot probes on every startup | probe exit logs; `test_topology.py`; live drill per `manual-tests/phase-5` |
| CC6.7 Data-in-transit restrictions | Outbound DLP: secrets/PII redacted from LLM prompts and tool-call arguments in flight; seed phrases and injections block outright; HTTPS-only egress in strict mode | redaction receipts (class+count); `SECRET_BLOCKED` / `SEED_PHRASE_BLOCKED` receipts |
| CC6.8 Unauthorized/malicious software | Skill guard screens + pins agent instruction files; MCP descriptor pinning (drift = withheld until re-approval); learned rules only load from Ed25519-signed bundles; images cosign-signed with SBOM attached | `SKILL_POISONED`/`SKILL_DRIFT`/`TOOL_DESCRIPTOR_DRIFT` receipts; cosign verification output |
| CC7.1 Monitoring for anomalies | Every network call, tool call, memory op, and inter-agent message scanned (L2 normalization defeats evasion) and receipted | scan findings, MITRE/OWASP-tagged, in receipts |
| CC7.2 Anomaly analysis and alerting | Blocks export as ECS alerts with `threat.technique.id`; each alert carries `record_hash`+`sig` back to a verifiable receipt | SIEM alert stream; `al export --verdict block` |
| CC7.3 / CC7.4 Incident evaluation and response | Kill switch (deny-all, four sources, receipted CRITICAL, health stays answerable); memory quarantine preserves hostile payloads for forensics outside the active store; snapshot + rollback restores known-good | kill-switch receipts; quarantine listing; rollback before/after hashes |
| CC7.5 Recovery and post-incident | Rollback to snapshots; learning loop turns the incident into a signed rule + generated regression test (the incident cannot silently recur) | rule bundle + its generated test in the suite |
| CC8.1 Change management | Config: unknown keys refused, permissive settings gated to audit mode, applied changes signed; learned rules pass a human review gate before signing; every past bypass is a permanent regression test | `config_change` receipts; bundle approval records (`--by`) |

## Additional criteria

| Criteria | Mechanism |
|----------|-----------|
| A1.1 (Availability) | Rate + data budgets prevent runaway loops (denial-of-wallet); budget accounting race-proof under concurrent writers (Postgres, tested with 16 writers); kill-switch denials deliberately do not flood the ledger |
| C1.1 (Confidentiality) | Receipts carry finding class + count, never content plaintext; provider keys are `SecretStr` from env/secrets, never logged or receipted; cross-tenant evidence reads return 404 (existence is a leak); the evidence ledger is local to the deployer |

## The evidence advantage

SOC 2 evidence is normally screenshots and log exports the auditee controls.
Here, the control's own output is signed and hash-chained: an auditor can
take a copy of the ledger and a public key and verify every record with the
standalone `al-verify` — including that nothing was inserted, reordered, or
removed. Per-org posture attestations state the mode that was actually
enforcing during the period, at a computed evidence level that audit mode
cannot fake.
