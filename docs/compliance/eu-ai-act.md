# EU AI Act mapping (planning aid)

AgentLighthouse is **operator tooling**, not an AI system under assessment:
it sits under an agentic AI deployment and produces the logging, oversight,
and robustness machinery several AI Act obligations require. If your agent
system is high-risk under the Act, these are the articles the plane
materially helps you implement. Planning aid — obtain your own legal
analysis; article numbers refer to Regulation (EU) 2024/1689.

| Obligation | What the Act asks | What the plane provides |
|------------|-------------------|-------------------------|
| Art. 9 — Risk management system | Identified, analysed, mitigated risks across the lifecycle | A layered, testable control stack (L0 egress choke-point through L6 kill switch) mapped to a named threat taxonomy (OWASP Agentic, MITRE ATT&CK); the README's "What this does NOT do" section is the standing honest risk register; the learning loop turns observed attacks into signed, human-reviewed rules with generated regression tests |
| Art. 12 — Record-keeping | Automatic recording of events over the system's lifetime, appropriate for traceability | Every mediated decision (network call, tool call, memory op, inter-agent message, config change, kill-switch action) is a signed, hash-chained receipt with actor, action, target, verdict, and findings; tamper-evident by construction and verifiable by third parties with `al-verify` alone |
| Art. 14 — Human oversight | Humans can effectively oversee, intervene, and interrupt | HITL gate: irreversible verbs (send/delete/transfer/pay/deploy...) pause for human approval, timeout denies; tainted sessions widen the pause set; the kill switch is the Art. 14 "stop button" — four sources, deny-all at every ingress, receipted, drillable |
| Art. 15 — Accuracy, robustness, cybersecurity | Resilience against attacks including **data/model poisoning and adversarial inputs** | Injection detection over six-pass evasion normalization; memory guard against context/memory poisoning (ASI06) with integrity baselines, quarantine, rollback; MCP descriptor pinning and tool-response scanning; A2A card pinning and session-smuggling checks; fail-closed engineering throughout (a crashed scanner denies) |
| Art. 26 — Deployer obligations | Monitor operation, keep logs under your control, suspend on incident | Dashboard + SIEM export for monitoring; ledgers are local files under the deployer's control (self-hosted only); kill switch for suspension; signed attestations document the posture that was actually running |
| Art. 72 — Post-market monitoring | Systematic collection and review of operational experience | Audit-mode rollout collects a would-block corpus without breaking workflows (`docs/rollout.md`); trends and breakdowns in the dashboard; per-org posture attestations on a cadence provide the review artifact |

## What this mapping does NOT claim

- No conformity assessment, CE marking, or classification of your system —
  those attach to the AI system and its provider/deployer, not to this
  tooling.
- Transparency obligations toward end users (Art. 50) and data-governance
  duties on training data (Art. 10) are outside a runtime mediation plane.
- The receipts record decisions and findings by class and count — they
  deliberately carry no content plaintext, which serves data-minimisation
  but means content-level forensics live in the quarantine, not the ledger.
