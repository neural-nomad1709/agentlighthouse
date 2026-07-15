# OWASP_MAPPING.md — OWASP Agentic Top 10 (2026) Coverage

> **Taxonomy verified 2026-07-10** against the official OWASP GenAI Security Project publication (genai.owasp.org) and corroborated across F5, Auth0, Teleport, Promptfoo, Modulos, Giskard. The prior internal mapping in MVP_PLAN.md was WRONG (it treated ASI01 as "injection", ASI05 as "exec deny", etc.). This is the corrected canonical mapping. Compliance claims are engineering planning aids, not legal opinions.

---

## The correct 2026 list

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

**OWASP's own through-line: "Least Agency" + managed per-agent identity.** This is exactly D1 (our moat = identity/governance/evidence). Identity controls blast radius even for the risks it can't stop at source (ASI04/ASI05/ASI08).

---

## AgentLighthouse coverage

| ID | Coverage | Mechanism | Layer / Phase |
|----|----------|-----------|---------------|
| **ASI01** Goal Hijack | **Strong** | L2 normalization + L3 injection detection (direct + indirect); taint escalation on untrusted-content ingestion; tool-response scanning before agent sees it | L2/L3/L4 · P2, P3 |
| **ASI02** Tool Misuse | **Strong (moat)** | Identity-bound default-deny tool policy with argument constraints; MCP tool-poisoning detection; chain detection (subsequence + gaps) | L4 · P3 |
| **ASI03** Identity & Privilege Abuse | **Strong (moat)** | Per-agent SPIFFE-style identity; least-privilege policy bound to identity; per-agent keys/budgets; identity in every receipt; no identity → deny | L4 + governance · P0, P3, P6 |
| **ASI04** Agentic Supply Chain | **Partial→Good** | MCP descriptor pinning (rug-pull/drift detection); tool allowlist; reused-OSS version+hash pinning + NOTICE + signed rule bundles. Cannot fix an upstream lib CVE at source (identity contains blast radius) | L1/L4 + supply-chain hygiene · P3, P7 |
| **ASI05** Unexpected Code Execution | **Good (contain, not prevent)** | Default-deny on exec/shell tools; HITL on irreversible verbs; container hardening (non-root, cap_drop ALL, read-only, no-new-privileges); egress choke-point limits post-RCE pivot. Kernel sandbox (full prevention) = Level 4 deferred | L4 + runtime · P3, P8 |
| **ASI06** Memory & Context Poisoning | **Strong (shipped P4)** | Guarded memory reads/writes (allow/redact/quarantine/block); SHA-256 integrity baselines on protected keys (out-of-band tamper caught on read); snapshot + rollback. `make demo-memory` | L5 · P4 |
| **ASI07** Insecure Inter-Agent Comms | **Strong (harness shipped P7; transport pending)** | A2A mediator in `core/al_core/a2a/`: Agent-Card poison-scan **and** pinning (drift = rug-pull), session id bound to its peer pair (replay = smuggling), payload scanned, peer message taints the session. All receipted (ASI07). `make demo-a2a`. What a real multi-agent partner adds is a *transport* (HTTP/gRPC), not new policy | L1/L4 · P7 |
| **ASI08** Cascading Failures | **Good** | Per-agent + per-domain budgets/rate limits (denial-of-wallet/loop-storm guard); circuit breakers; kill switch (≥3 sources); fail-closed everywhere stops error propagation | L3/L4 + control · P2, P5 |
| **ASI09** Human-Agent Trust Exploitation | **Good** | HITL approval gates on irreversible actions; explainable intercepts (fixed `block_reason` vocabulary in receipts + dashboard); output scanning | L4/L6 · P3, P5 |
| **ASI10** Rogue Agents | **Strong** | Learning loop shipped P7 (block → mined rule → human review → **signed** bundle → auto-generated regression test; an unsigned bundle is refused, so the loop can never be used to teach the plane to *allow*); default-deny means an off-policy agent is denied by construction; kill switch (4 sources); signed evidence proves what a rogue agent attempted | L4/L6 + control · P5, P7 |

## Honesty on Goal 5 ("solve all ten")

**As of Phase 7 (2026-07-12), all ten have shipped mechanisms with tests behind them.** The honest split has not changed — shipping does not upgrade a *contained* risk into a *prevented* one:

- **Prevented at source:** ASI01, ASI02, ASI03, ASI06, ASI07, ASI09, ASI10.
- **Contained, not prevented at source (by design; identity limits blast radius — matches OWASP's own guidance):** ASI04, ASI05, ASI08.

ASI07 moves from "interface-ready" to **prevented at source**: the mediation, pinning, smuggling checks and receipts are real code with a passing harness (`make demo-a2a`). What a multi-agent partner still supplies is a *transport*, not policy — the same distinction Phase 5 settled for MCP.

No honest product "solves" ASI04/05/08 at source without owning the upstream supply chain and the OS kernel. The claim to make is precise: **all ten are addressed; seven are prevented at source, three are contained via least-agency + hardening.** State it that way to a security reviewer and it survives scrutiny; claim "we solve all 10 completely" and it won't.

## MITRE ATT&CK tags — the set actually emitted in receipts (verified 2026-07-12)

`T1041` exfil over C2 channel · `T1059` command/scripting · `T1078` valid
accounts / identity abuse · `T1134` access-token manipulation (A2A session
smuggling) · `T1195` supply-chain compromise (MCP descriptor + Agent-Card
drift) · `T1204` user execution / trust exploitation (poisoning) · `T1552` +
`T1552.005` credentials in files / cloud metadata · `T1565` data manipulation
(memory tamper).

Attached per-finding and surfaced by `al export` as `threat.technique.id`
(ECS), so a SOC can pivot on the technique without knowing anything about
AgentLighthouse. This list is the emitted set, not an aspiration — a tag we do
not attach is not listed.
