# OWASP Agentic Top 10 (2026) coverage

> The taxonomy below follows the OWASP GenAI Security Project publication (genai.owasp.org). Compliance claims are engineering planning aids, not legal opinions.

---

## The 2026 list

| ID | Name | Meaning |
|----|------|---------|
| ASI01 | Agent Goal Hijack | Adversary redirects the agent's plan/objective (direct or indirect injection via docs, tool responses, agent messages) |
| ASI02 | Tool Misuse & Exploitation | Agent invokes a legitimate tool with parameters/sequence outside authorized use; tool-interface exploitation, tool poisoning |
| ASI03 | Identity & Privilege Abuse | Agent credentials/tokens/inherited permissions misused or escalated |
| ASI04 | Agentic Supply Chain Vulnerabilities | Third-party tools, frameworks, registries, MCP servers compromised at source; dynamic runtime composition |
| ASI05 | Unexpected Code Execution (RCE) | Adversarial code/command execution → host/container compromise, sandbox escape |
| ASI06 | Memory & Context Poisoning | Persistent memory/retrieval/context shaped to mislead future steps |
| ASI07 | Insecure Inter-Agent Communication | Messages between agents spoofed, replayed, unauthenticated |
| ASI08 | Cascading Failures | Error/compromise in one agent fans out across the system |
| ASI09 | Human-Agent Trust Exploitation | Humans over-trust or are deceived by agent output into harmful actions |
| ASI10 | Rogue Agents | Agent operates outside policy — by design failure, drift, or compromise |

**OWASP's through-line is "Least Agency" plus managed per-agent identity.** AgentLighthouse is built on the same idea: identity, least privilege and evidence. Identity limits blast radius even for the risks that cannot be stopped at source (ASI04, ASI05, ASI08).

---

## AgentLighthouse coverage

| ID | Coverage | Mechanism | Layer |
|----|----------|-----------|-------|
| **ASI01** Goal Hijack | **Prevented** | L2 normalization + L3 injection detection (direct + indirect); taint escalation on untrusted-content ingestion; tool-response scanning before the agent sees it. `make demo` | L2/L3/L4 |
| **ASI02** Tool Misuse | **Prevented** | Identity-bound default-deny tool policy with argument constraints; MCP tool-poisoning detection; chain detection (ordered subsequence with gap tolerance) | L4 |
| **ASI03** Identity & Privilege Abuse | **Prevented** | Per-agent SPIFFE-style identity; least-privilege policy bound to identity; per-agent keys and budgets; identity in every receipt; no identity → deny | L4 + governance |
| **ASI04** Agentic Supply Chain | **Contained** | MCP descriptor pinning (rug-pull/drift detection); tool allowlist; version- and hash-pinned dependencies; signed rule bundles. A mediator cannot fix an upstream library vulnerability at source; identity contains the blast radius | L1/L4 + supply-chain hygiene |
| **ASI05** Unexpected Code Execution | **Contained** | Default-deny on exec/shell tools; human approval on irreversible verbs; container hardening (non-root, cap_drop ALL, read-only, no-new-privileges); the egress choke-point limits a pivot after code execution. An optional gVisor runtime profile is provided | L4 + runtime |
| **ASI06** Memory & Context Poisoning | **Prevented** | Guarded memory reads/writes (allow/redact/quarantine/block); SHA-256 integrity baselines on protected keys (out-of-band tamper caught on read); snapshot + rollback. `make demo-memory` | L5 |
| **ASI07** Insecure Inter-Agent Comms | **Prevented** | A2A mediator in `core/al_core/a2a/`: Agent-Card poison-scan **and** pinning (drift = rug-pull), session id bound to its peer pair (replay = smuggling), payload scanned, peer message taints the session. All receipted. `make demo-a2a`. Sender identity is asserted, not cryptographically proven | L1/L4 |
| **ASI08** Cascading Failures | **Contained** | Per-agent and per-domain budgets and rate limits (denial-of-wallet and loop-storm guard); kill switch (four sources); fail-closed everywhere stops error propagation | L3/L4 + control |
| **ASI09** Human-Agent Trust Exploitation | **Prevented** | Human approval gates on irreversible actions; explainable intercepts (fixed `block_reason` vocabulary in receipts and the dashboard); output scanning | L4/L6 |
| **ASI10** Rogue Agents | **Prevented** | Default-deny means an off-policy agent is denied by construction; kill switch (four sources); signed evidence proves what a rogue agent attempted; the learning loop (block → mined rule → human review → **signed** bundle → generated regression test) refuses an unsigned bundle, so it cannot be used to teach the mediator to *allow* | L4/L6 + control |

## Prevented versus contained

All ten risks have a mechanism with tests behind it. The split is deliberate, and a mechanism does not turn a *contained* risk into a *prevented* one:

- **Prevented at source:** ASI01, ASI02, ASI03, ASI06, ASI07, ASI09, ASI10.
- **Contained, not prevented at source:** ASI04, ASI05, ASI08. Identity and least agency limit the blast radius, which matches OWASP's own guidance.

No mediator prevents ASI04, ASI05 or ASI08 at source without owning the upstream supply chain and the operating-system kernel. The precise claim is: **all ten are addressed; seven are prevented at source, three are contained through least agency and hardening.**

The limits of each mechanism are stated in the README's "What This Does Not Do" section.

## MITRE ATT&CK tags emitted in receipts

`T1041` exfil over C2 channel · `T1059` command/scripting · `T1078` valid
accounts / identity abuse · `T1134` access-token manipulation (A2A session
smuggling) · `T1195` supply-chain compromise (MCP descriptor + Agent-Card
drift) · `T1204` user execution / trust exploitation (poisoning) · `T1552` +
`T1552.005` credentials in files / cloud metadata · `T1565` data manipulation
(memory tamper).

Attached per finding and surfaced by `al export` as `threat.technique.id`
(ECS), so a SOC can pivot on the technique without knowing anything about
AgentLighthouse. This is the emitted set: a tag the mediator does not attach is
not listed.
