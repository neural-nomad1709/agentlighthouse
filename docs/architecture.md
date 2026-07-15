# AgentLighthouse Architecture

> Seven security layers, operated as four gates, with a physically segregated control plane. Everything fails closed. Every decision is receipted.

## Build status (2026-07-12, after Phase 7)

**All seven layers and all four gates are implemented.** L0–L6 ship with tests;
the control/data plane split is enforced by the compose topology and *proved on
every `up`* by a one-shot probe that must fail to reach the control plane before
any agent starts.

| Layer | Status |
|-------|--------|
| L0 Egress firewall | ✅ boot bypass self-test + nftables ruleset (netns test is Linux-gated) |
| L1 Protocol mediation | ✅ forward / fetch / OpenAI+Anthropic reverse / **MCP on 3 transports** / **A2A** (mediator shipped; wire transport pending) |
| L2 Normalization | ✅ six passes, bounded scan variants |
| L3 Detection | ✅ Scanner interface + adapters + fail-closed verdict engine; **learned rules plug into the same seam** |
| L4 Capability & taint | ✅ identity-bound default-deny, arg constraints, chain detection, HITL, taint |
| L5 Memory Guard | ✅ screening, integrity baselines, quarantine, snapshot + rollback |
| L6 Evidence | ✅ signed hash-chained receipts, SQLite/**Postgres** mirror, **SIEM export**, kill switch, RBAC + tenancy, **signed posture attestation** |

Deferred by design (unchanged): TLS interception inside CONNECT tunnels, and a
kernel sandbox (gVisor) — Phase 8 makes the latter an optional profile.

---

## 1. Logical model

```
                ┌──────────────────── CONTROL PLANE (segregated Docker network) ────────────────────┐
                │  Policy Store · Identity Registry · RBAC · Kill Switch API · Dashboard · Learning  │
                └──────────▲──────────────────────────────────────────────────────────▲─────────────┘
                           │ hot-reload / signed config                               │ events
AGENT (isolated netns,     │                                                          │
no direct egress) ──────▶ ┌┴──────────────────── DATA PLANE (al-core) ────────────────┴───────────┐ ──▶ WORLD
                          │ L0  Egress Firewall   nftables default-deny; boot bypass self-test    │   (LLM providers,
                          │ L1  Protocol Mediation forward / fetch / OpenAI+Anthropic-reverse /   │    MCP servers,
                          │                        MCP (stdio+HTTP) / [A2A interface] / [WS P2]   │    web, tools,
                          │ L2  Normalization      NFKC, zero-width, homoglyph, leet, base64 (6x) │    other agents)
                          │ L3  Detection          injection · secrets · PII · SSRF · entropy ·   │
                          │                        rate-limit · data-budget · BIP-39              │
                          │ L4  Capability & Taint identity-bound default-deny tool policy; arg   │
                          │                        constraints; chain detection; HITL; taint esc. │
                          │ L5  Memory Guard       OWASP AMG adapter; read/write screen; rollback │
                          │ L6  Evidence           Ed25519 signed hash-chained receipts; JSONL;   │
                          │                        SQLite mirror; SIEM export                     │
                          └──────────────────────────────────────────────────────────────────────┘
```

## 2. Four operational gates (how the team runs it)

| Gate | Layers | Owns |
|------|--------|------|
| **Edge Gate** | L0 + L1 | Egress choke-point, proxy modes, DNS pinning, SSRF network controls, MCP/A2A wrapping |
| **Content Gate** | L2 + L3 | Normalization, injection, DLP/secrets, PII, entropy, rate/budget |
| **Action Gate** | L4 + L5 | Identity-bound tool policy, argument constraints, chain detection, HITL, taint escalation, memory guard |
| **Evidence & Control Gate** | L6 + ops | Signed receipts, JSONL/SQLite, kill switch, RBAC, config validation, dashboard |

## 3. Layer specifications

### L0 — Egress firewall (Level-1 "OS" property)
- nftables default-deny inside the agent network namespace; the ONLY permitted route is al-core.
- **Boot self-test:** open a raw socket to a known external IP bypassing al-core. If it connects → log CRITICAL, emit signed failure receipt, **refuse to start**.
- Compose topology: agent services on `agent-net` (internal: true), al-core bridges `agent-net` ↔ `egress-net`; control services on `control-net` only.

### L1 — Protocol mediation (one service, multiple ingress modes)
- **Forward proxy** (HTTP CONNECT via `HTTPS_PROXY`) — zero agent code change.
- **Fetch proxy** (`GET /fetch?url=`).
- **Reverse proxy** — OpenAI-compatible (`/v1/chat/completions`) + Anthropic-compatible (`/v1/messages`); per-user virtual-key auth + budget check; SSE passthrough with fail-closed scanning.
- **MCP proxy** — stdio wrap (`al mcp proxy -- npx server`) + Streamable HTTP upstream; bidirectional scan.
- **A2A mediation interface** — see §6. Interface from Phase 0; feature behind demo harness.
- DNS pinning (resolve once, pin IP, re-verify on connect) → kills rebinding.
- WebSocket proxy **[P2]**; TLS interception (CONNECT MITM) **[deferred]**.

### L2 — Normalization (6 passes, re-scan after each)
NFKC → zero-width strip → homoglyph fold → leetspeak → vowel/space collapse → base64/hex unwrap (bounded depth).

### L3 — Detection pipeline (uniform Scanner interface, swappable adapters)
| Scanner | Engine | Action default |
|---|---|---|
| injection | LLM Guard (primary) + Aigis-style tiered heuristics; LLM-judge deferred | block |
| secrets | Gitleaks rulesets / detect-secrets + entropy | block |
| pii | Presidio (optional compose profile) + regex core | redact to typed placeholders |
| ssrf | private/link-local/metadata CIDRs (169.254.169.254, 10/8, 127/8, 172.16/12, 192.168/16, fd00::/8) + rebind | block |
| entropy | path/subdomain Shannon thresholds (DNS-tunnel/base64 blob) | warn/block |
| rate/budget | per-domain RPS + per-domain byte budgets + per-agent call budgets (denial-of-wallet) | block |
| bip39 | seed-phrase sequence detection | block |

Verdict precedence: **block > strip > warn > ask > allow**. Scanner block overrides any allowlist/policy allow. Any scanner crash/timeout = block (fail closed).

### L4 — Capability & taint gate (THE MOAT — invest here)
- **Identity:** every agent has a registered identity `spiffe://<org>/agent/<name>` (Phase 0 registry). Requests carry identity via authenticated header + per-agent key; receipts bind to it. No identity → deny.
- **Default-deny tool policy** per identity, with **argument constraints**:
```yaml
agents:
  claude-code:
    allow:
      - { tool: http_fetch, args: { url: { allow_hosts: [docs.python.org, api.internal] } } }
      - { tool: read_file,  args: { path: { allow_prefixes: [/workspace/], deny_prefixes: [/etc/, /secrets/] } } }
    deny: [ { tool: exec_shell } ]
    budgets: { max_tool_calls_per_min: 60, max_outbound_bytes: 1048576 }
```
- **Tool descriptor pinning:** hash tool descriptions on first sight; drift = rug-pull alert + block until re-approved.
- **Chain detection:** subsequence match with gap tolerance (recon → stage → exfil through benign interleaving).
- **HITL:** irreversible verbs (send/delete/transfer/publish/deploy) require human approval via control plane; timeout = deny.
- **Taint escalation:** session that ingested untrusted content (web fetch, unpinned tool output) gets elevated scanning + tightened policy on subsequent protected operations.

### L5 — Memory Guard (ASI06; **shipped Phase 4** — a core feature, not a compose profile)
- Adapter around **OWASP Agent Memory Guard**: screen every memory read/write; SHA-256 integrity baselines on protected keys; detect injection/leakage/protected-key modification/size anomaly/self-reinforcement; actions allow/redact/quarantine/block via YAML; snapshot + rollback to known-good.

### L6 — Evidence (MIT-licensed spec — publish first)
Receipt v1 (RFC 8785 JCS canonicalization; SHA-256 chain; Ed25519 mediator signature):
```jsonc
{
  "v": 1, "seq": 42, "ts": "2026-07-10T12:00:00.000Z",
  "actor": "spiffe://acme/agent/claude-code",
  "action": "mcp_tool_call",            // http_forward|fetch|llm_call|mcp_tool_call|mcp_tool_result|memory_read|memory_write|a2a_message|config_change|killswitch
  "target": "tool:send_email",
  "verdict": "block",
  "findings": [ { "scanner": "tool_policy", "rule_id": "policy.default_deny", "severity": "high", "owasp": "ASI03", "mitre": "T1078" } ],
  "block_reason": "TOOL_NOT_ALLOWED",   // fixed machine-readable vocabulary + retry hint (agent-legible denials)
  "policy_hash": "sha256:...",
  "redaction": { "aws-access-key": 1 }, // class counts only, never plaintext
  "prev_hash": "sha256:...", "record_hash": "sha256:...",
  "sig": "ed25519:..."
}
```
- Canonical store: append-only JSONL. Mirror: SQLite WAL (query only). Checkpoint every 100 records. SIEM/webhook export with MITRE tags. Standalone verifier package (`al-verify`, minimal deps) — third parties verify without al-core.

## 4. Trust boundaries

| Boundary | Trust | Rule |
|---|---|---|
| Agent runtime | Untrusted | No direct internet; no control-plane route; identity required |
| al-core | Trusted mediator | Fails closed on scanner/config/storage failure |
| LLM providers | Untrusted external | Scanned both directions |
| MCP tools | Semi-trusted | Descriptor pinned; drift checked; responses scanned |
| Other agents (A2A) | Untrusted | Mediated + scanned like any external input |
| Memory store | Sensitive | Guarded reads/writes; rollback |
| Dashboard/API | Privileged | Control network only; RBAC; no agent access |
| JSONL evidence | Audit source of truth | Append-only + hash chain + signature |

## 5. Control plane / data plane separation
Kill switch API, admin API, policy store, dashboard on `control-net`. Agent containers cannot route to it — enforced by network topology, verified by test (agent → control-net connection attempt must fail). Kill switch has ≥3 independent activation sources: API (control-net), sentinel file, SIGUSR1 — each drills to full deny-all.

**Evidence pool (read side).** Separation gives each plane its own ledger with its own single writer, which means the dashboard — a control-plane citizen — can see only control-plane receipts, while every decision an operator cares about is written by the gateway. `core/al_core/audit/pool.py` closes that gap on the **read side only**: the control plane attaches the data plane's live mirror **read-only** (SQLite `mode=ro`; a write raises) plus its public key, then serves merged, plane-tagged, org-scoped receipts and verifies each chain separately. The one-writer-per-chain invariant therefore holds *by construction*, not by discipline — there is no code path by which the control plane can write another plane's chain. Wiring: `control.dataplane_dir` / `control.dataplane_pubkey` (compose mounts the `al-data` volume at `/app/dataplane`).

Chain status distinguishes **`invalid`** (signatures checked, they failed → tampering) from **`unavailable`** (no readable key or ledger → we could not check). Both are fail-closed and never reported as verified, but only the first is the alarm; collapsing them would make the tamper signal cry wolf on a misconfiguration.

## 6. A2A mediation (**shipped Phase 7** — mediator + harness; wire transport pending)

Delivered in `core/al_core/a2a/`: Agent Cards are poison-scanned **and pinned**
(drift = rug-pull), a session id is bound to the peer pair that opened it (replay
by a third agent = smuggling, denied), payloads run through L2/L3, and a peer
message taints the receiving session. All receipted as `a2a_message` (ASI07);
`make demo-a2a` proves it between two mock agents. What a real multi-agent
partner still supplies is a *transport* (HTTP/gRPC), not policy.

The interface below is unchanged from Phase 0 — it was threaded early so this was
never a retrofit, and it wasn't:
```python
class AgentMessageMediator(Protocol):
    async def mediate(self, msg: AgentEnvelope) -> Verdict: ...

class AgentEnvelope(BaseModel):
    protocol: Literal["a2a", "custom"]
    sender: str          # spiffe id or agent card ref
    recipient: str
    agent_card: dict | None   # pinned + drift-checked like MCP descriptors
    payload: bytes
    session_id: str
```
- Scanning path reuses L2+L3 wholesale; adds Agent-Card pinning (poisoning/drift) and session-continuity checks (smuggling).
- **Demo harness** (test compose profile): two mock agents; one attempts Agent-Card poisoning + session smuggling; al-core intercepts between them. This IS the partner demo ([`demos.md`](demos.md)).
- Graduates to production feature when a design partner runs real multi-agent topology.

## 7. Learning loop (**shipped Phase 7**)
Detection event → miner proposes rule → human review gate → approved rule shipped as signed bundle → auto-generated regression test. Signature verified on bundle load; unsigned bundle → refuse.

As built, with one constraint the plan did not anticipate: **receipts carry no
plaintext by design**, so the miner *cannot* read attack strings out of the
ledger. It mines what is honestly available — repeated block **targets** from
receipts (the thing acted upon, not the content) and real payloads from the
memory **quarantine** (which exists so a human can inspect them). Candidates are
inert; only a human-signed bundle enforces, and `load_bundle` verifies *before*
it loads, so the loop can never be used to teach the plane to **allow**.
