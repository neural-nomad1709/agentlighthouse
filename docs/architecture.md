# AgentLighthouse Architecture

> Seven security layers, operated as four gates, with a physically segregated control plane. Everything fails closed. Every decision is receipted.

## Layers at a glance

The control/data plane split is enforced by the compose topology and proved on
every `up` by a one-shot probe that must fail to reach the control plane before
any agent starts.

| Layer | What it provides |
|-------|------------------|
| L0 Egress firewall | Boot bypass self-test and an nftables default-deny ruleset |
| L1 Protocol mediation | Forward, fetch, OpenAI- and Anthropic-compatible reverse proxies, MCP on three transports, A2A mediation |
| L2 Normalization | Six passes, bounded scan variants |
| L3 Detection | Scanner interface, adapters and a fail-closed verdict engine; learned rules plug into the same interface |
| L4 Capability & taint | Identity-bound default-deny policy, argument constraints, chain detection, human approval, taint |
| L5 Memory Guard | Screening, integrity baselines, quarantine, snapshot and rollback |
| L6 Evidence | Signed hash-chained receipts, SQLite or Postgres mirror, SIEM export, kill switch, RBAC and tenancy, signed posture attestation |

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
                          │                        MCP (stdio+HTTP) / A2A mediation               │    web, tools,
                          │ L2  Normalization      NFKC, zero-width, homoglyph, leet, base64 (6x) │    other agents)
                          │ L3  Detection          injection · secrets · PII · SSRF · entropy ·   │
                          │                        rate-limit · data-budget · BIP-39              │
                          │ L4  Capability & Taint identity-bound default-deny tool policy; arg   │
                          │                        constraints; chain detection; HITL; taint esc. │
                          │ L5  Memory Guard       screened reads/writes; baselines; rollback     │
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
- **MCP proxy** — stdio wrap (`al mcp proxy -- npx server`) + Streamable HTTP upstream; bidirectional scan. Every server reply is scanned whatever the method; replies are relayed only for an in-flight request, once; `tools/call` is allowed only for tools the agent was shown in `tools/list`; server-initiated requests are scanned and, when refused, still answered; the agent's answers to them are DLP-scanned on the way out.
- **A2A mediation** — see §6.
- DNS pinning (resolve once, pin IP, re-verify on connect) → kills rebinding.
- The forward proxy tunnels TLS opaquely: it enforces on destination host, port and pinned IP, and does not inspect content inside a CONNECT tunnel.

### L2 — Normalization (6 passes, re-scan after each)
NFKC → zero-width strip → homoglyph fold → leetspeak → vowel/space collapse → base64/hex unwrap (bounded depth).

### L3 — Detection pipeline (uniform Scanner interface, swappable adapters)
| Scanner | Engine | Action default |
|---|---|---|
| injection | Tiered heuristics over every normalized variant | block |
| secrets | Provider key and token patterns, private keys, high-entropy assignments; optional `detect-secrets` adapter | redact (block when seen only in a decoded variant) |
| pii | Email, phone, SSN and Luhn-checked card patterns | redact to typed placeholders |
| ssrf | private/link-local/metadata CIDRs (169.254.169.254, 10/8, 127/8, 172.16/12, 192.168/16, fd00::/8) + rebind | block |
| entropy | path/subdomain Shannon thresholds (DNS-tunnel/base64 blob) | warn/block |
| rate/budget | per-domain RPS + per-domain byte budgets + per-agent call budgets (denial-of-wallet) | block |
| url-shape | scheme, traversal and CRLF checks on URLs | block |
| bip39 | seed-phrase sequence detection | block |

The scanners are dependency-free pattern matching and heuristics behind one `Scanner` interface; they make no machine-learning judgement.

Verdict precedence: **block > strip > warn > ask > allow**. Scanner block overrides any allowlist/policy allow. Any scanner crash/timeout = block (fail closed).

### L4 — Capability & taint gate
- **Identity:** every agent has a registered identity `spiffe://<org>/agent/<name>`. Requests carry identity via authenticated header + per-agent key; receipts bind to it. No identity → deny.
- **Default-deny tool policy** per identity, with **argument constraints**:
```yaml
agents:
  claude-code:
    allow:
      - { tool: http_fetch, args: { url: { allow_hosts: [docs.python.org, api.internal] } } }
      - { tool: read_file,  args: { path: { allow_prefixes: [/workspace/], deny_prefixes: [/etc/, /secrets/] } } }
    deny: [ { tool: exec_shell } ]
    budgets: { max_tool_calls_per_min: 60 }
```
  Path prefixes are checked after percent-decoding, stripping a local `file://`, collapsing repeated slashes and `..`. Symlinks are not resolved: the mediator cannot see the tool's filesystem, so a link inside an allowed prefix must be contained by the tool or its sandbox.
- **Tool descriptor pinning:** hash tool descriptions on first sight; drift = rug-pull alert + block until re-approved.
- **Chain detection:** subsequence match with gap tolerance (recon → stage → exfil through benign interleaving).
- **HITL:** irreversible verbs (send/delete/transfer/publish/deploy) require human approval via control plane; timeout = deny. An approval is a single-use grant bound to actor, tool, argument digest and session: the agent retries the same call and the grant is spent once.
- **Taint escalation:** session that ingested untrusted content (web fetch, unpinned tool output) gets elevated scanning + tightened policy on subsequent protected operations.

### L5 — Memory Guard (ASI06)
- Every memory write and read is screened through the content gate: allow, redact, or block and quarantine. Protected keys carry SHA-256 integrity baselines in a mediator-owned file separate from the store, so an out-of-band edit is caught on read. Oversized values are denied. Snapshot and rollback restore a known-good state. The design is influenced by OWASP Agent Memory Guard; the implementation is independent.

### L6 — Evidence (MIT-licensed spec)
Receipt v1 (RFC 8785 JCS canonicalization; SHA-256 chain; Ed25519 mediator signature):
```jsonc
{
  "v": 1, "seq": 42, "ts": "2026-07-10T12:00:00.000Z",
  "actor": "spiffe://acme/agent/claude-code",
  "action": "mcp_tool_call",            // http_forward|fetch|llm_call|mcp_tool_call|mcp_tool_result|mcp_client_reply|memory_read|memory_write|skill_load|a2a_message|config_change|killswitch|remote_exec|session_open|session_close|permission_request
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
- Canonical store: append-only JSONL. Mirror: SQLite WAL or Postgres (query only). SIEM export with MITRE tags. Standalone verifier package (`al-verify`, minimal deps) — third parties verify without al-core.

## 4. Trust boundaries

| Boundary | Trust | Rule |
|---|---|---|
| Agent runtime | Untrusted | No direct internet; no control-plane route; identity required |
| al-core | Trusted mediator | Fails closed on scanner/config/storage failure |
| LLM providers | Untrusted external | Scanned both directions |
| MCP tools | Semi-trusted | Descriptor pinned; drift checked; only advertised tools callable; every reply and server request scanned |
| Other agents (A2A) | Untrusted | Mediated + scanned like any external input |
| Memory store | Sensitive | Guarded reads/writes; rollback |
| Dashboard/API | Privileged | Control network only; RBAC; no agent access |
| JSONL evidence | Audit source of truth | Append-only + hash chain + signature |

## 5. Control plane / data plane separation
Kill switch API, admin API, policy store, dashboard on `control-net`. Agent containers cannot route to it — enforced by network topology, verified by test (agent → control-net connection attempt must fail). The kill switch has four independent activation sources: the control API, the `al killswitch` command, a sentinel file and SIGUSR1. Each drills to full deny-all.

**Evidence pool (read side).** Separation gives each plane its own ledger with its own single writer, which means the dashboard — a control-plane citizen — can see only control-plane receipts, while every decision an operator cares about is written by the gateway. `core/al_core/audit/pool.py` closes that gap on the **read side only**: the control plane attaches the data plane's live mirror **read-only** (SQLite `mode=ro`; a write raises) plus its public key, then serves merged, plane-tagged, org-scoped receipts and verifies each chain separately. The one-writer-per-chain invariant therefore holds *by construction*, not by discipline — there is no code path by which the control plane can write another plane's chain. Wiring: `control.dataplane_dir` / `control.dataplane_pubkey` (compose mounts the `al-data` volume at `/app/dataplane`, read-only at the mount, so the guarantee does not rest on this code). HITL approvals are the one thing the control plane writes for the data plane; they cross on a separate small volume (`control.approvals_dir`), and the data plane's private signing key sits on a volume the control plane never mounts.

Chain status distinguishes **`invalid`** (signatures checked, they failed → tampering) from **`unavailable`** (no readable key or ledger → we could not check). Both are fail-closed and never reported as verified, but only the first is the alarm; collapsing them would make the tamper signal cry wolf on a misconfiguration.

## 6. A2A mediation

Delivered in `core/al_core/a2a/`: Agent Cards are poison-scanned **and pinned**
(drift = rug-pull), a session id is bound to the peer pair that opened it (replay
by a third agent = smuggling, denied), payloads run through L2/L3, and a peer
message taints the receiving session. All receipted as `a2a_message` (ASI07);
`make demo-a2a` exercises it between two mock agents. The mediator is
transport-agnostic: it decides on an envelope and does not itself carry
messages between agents over the network. Sender identity is asserted, not
cryptographically proven.

The mediation interface:
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
- **Demo:** two mock agents; one attempts Agent-Card poisoning and session smuggling; the mediator intercepts between them ([`demos.md`](demos.md)).

## 7. Learning loop
Detection event → miner proposes rule → human review gate → approved rule shipped as signed bundle → auto-generated regression test. Signature verified on bundle load; unsigned bundle → refuse.

One constraint shapes the miner: **receipts carry no
plaintext by design**, so the miner *cannot* read attack strings out of the
ledger. It mines what is available — repeated block **targets** from
receipts (the thing acted upon, not the content) and real payloads from the
memory **quarantine** (which exists so a human can inspect them). Candidates are
inert; only a human-signed bundle enforces, and `load_bundle` verifies *before*
it loads, so the loop can never be used to teach the plane to **allow**.
