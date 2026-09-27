![AgentLighthouse](assets/banner-1.png)

# AgentLighthouse

**The runtime security and governance plane for AI agents.**

A mandatory, verified choke-point that mediates every network call, tool call,
memory operation, and inter-agent message an agent makes; enforces
identity-bound least privilege; and emits **mediator-signed, hash-chained,
independently verifiable evidence** of every decision it takes.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)
![Tests](https://img.shields.io/badge/tests-699-brightgreen.svg)
![Evidence](https://img.shields.io/badge/evidence-Ed25519%20%2B%20RFC%208785-informational.svg)
![Status](https://img.shields.io/badge/status-pilot%2Fdesign--partner-orange.svg)
[![Docker Image](https://img.shields.io/badge/docker-amitkala%2Fagentlighthouse%3Av1.0-2496ED.svg?logo=docker&logoColor=white)](https://hub.docker.com/r/amitkala/agentlighthouse)

> Runs on a laptop for evaluation; ships as a hardened, signed container for
> production. Every claim in this document maps to a shipped, tested mechanism.
> Where a capability is not yet delivered, it is named plainly in
> [What This Does Not Do](#what-this-does-not-do).

**Source:** <https://github.com/neural-nomad1709/agentlighthouse> &nbsp;·&nbsp; **Image:** `docker pull amitkala/agentlighthouse:v1.0`

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Why This Project Exists](#why-this-project-exists)
- [Business Value](#business-value)
- [Core Capabilities](#core-capabilities)
- [Architecture Overview](#architecture-overview)
  - [System Architecture](#system-architecture)
  - [Component Interaction](#component-interaction)
  - [Request Flow](#request-flow)
  - [Request Lifecycle](#request-lifecycle)
  - [Evidence Data Flow](#evidence-data-flow)
  - [Integration Modes](#integration-modes)
- [The Evidence Format](#the-evidence-format)
- [Security Model](#security-model)
- [Governance Model](#governance-model)
- [Standards and Compliance](#standards-and-compliance)
- [Technology Stack](#technology-stack)
- [Repository Structure](#repository-structure)
- [Getting Started](#getting-started)
- [Deployment Models](#deployment-models)
- [Configuration and Rollout](#configuration-and-rollout)
- [Usage Examples](#usage-examples)
- [Command Reference](#command-reference)
- [Observability](#observability)
- [Production Readiness](#production-readiness)
- [CI/CD and Supply-Chain Integrity](#cicd-and-supply-chain-integrity)
- [Enterprise Adoption Guide](#enterprise-adoption-guide)
- [Build vs Buy](#build-vs-buy)
- [Roadmap](#roadmap)
- [What This Does Not Do](#what-this-does-not-do)
- [Contributing and Security Reporting](#contributing-and-security-reporting)
- [Testing](#testing)
- [Versioning](#versioning)
- [FAQ](#faq)
- [Glossary](#glossary)
- [License and Attribution](#license-and-attribution)

---

## Executive Summary

AI agents read untrusted text — a web page, a tool response, a peer agent's
message — and then **act** on it: calling tools, writing memory, sending data
out. That loop is the entire attack surface, and it cannot be secured from
inside the agent, because the agent is the component being manipulated.

AgentLighthouse sits **outside** the agent as a proxy the agent cannot route
around. It screens what goes in, authorizes what goes out, and writes a
**signed, tamper-evident receipt** for every decision. The receipts are the
product: anyone can verify them with a standalone tool whose only dependency is
`cryptography`, without running or trusting the rest of this codebase.

The design is a stack of seven security layers (L0–L6), operated as four gates,
with a physically segregated control plane. Everything fails closed. The system
is delivered as an MIT-licensed Python workspace and a hardened, cosign-signed
container image.

| Attribute | Value |
|---|---|
| What it is | Runtime security and governance plane (mediation proxy) for AI agents |
| Primary output | Ed25519-signed, hash-chained, independently verifiable decision receipts |
| Enforcement posture | Fail-closed, default-deny, identity-bound least privilege |
| Deployment | Self-hosted; laptop for evaluation, hardened container for production |
| License | MIT in its entirety |
| Maturity | Enforcement gates shipped and tested; pilot / design-partner stage |
| Language / runtime | Python 3.12+ |

## Why This Project Exists

Traditional application security assumes the code is the thing to be trusted and
the input is the thing to be filtered. Agentic systems invert this: the model is
non-deterministic, it treats retrieved text as instructions, and it holds
credentials and tool access. Guardrails placed **inside** the agent share the
agent's trust boundary — a successful prompt injection is already past them.

AgentLighthouse takes the position that the only defensible control point is a
**mediator the agent cannot bypass**, and that the only durable deliverable is
**evidence an auditor can verify without trusting the operator**. Detection depth
is a feature that can be improved with better engines; the choke-point, the
identity binding, and the signed evidence chain are the architecture.

## Business Value

AgentLighthouse is built for organizations deploying AI agents that touch real
systems, real data, and real money.

- **Risk reduction.** A default-deny, identity-bound choke-point contains the
  blast radius of a compromised or misbehaving agent — even for risks it cannot
  prevent at source, least agency limits what a rogue agent can do.
- **Auditability by construction.** Every mediated decision is a signed receipt.
  Security reviews, incident investigations, and compliance evidence draw from a
  tamper-evident ledger rather than best-effort logs.
- **Governance and cost control.** Per-agent and per-organization identities,
  budgets, RBAC, and signed posture attestations make agent fleets governable
  and their spend attributable.
- **Standards alignment.** Coverage is mapped to the OWASP Agentic Top 10, NIST
  SP 800-53, the EU AI Act, SOC 2, and the MCP threat model, with MITRE ATT&CK
  technique tags emitted directly into your SIEM.
- **No vendor lock-in on evidence.** The receipt format is a published,
  MIT-licensed specification; the verifier is standalone.

## Core Capabilities

| Domain | Capability |
|---|---|
| Network mediation | CONNECT forward proxy, fetch proxy, OpenAI- and Anthropic-compatible reverse proxy with SSE, MCP proxy (stdio and Streamable HTTP), A2A mediation |
| Egress control | Default-deny nftables ruleset with a boot self-test that refuses to start if out-of-band egress succeeds |
| Content inspection | Six-pass evasion-folding normalization plus a fail-closed detection engine (injection, secrets, PII, SSRF, entropy, BIP-39 seed phrases, rate and data budgets) |
| Capability control | Identity-bound default-deny tool policy with argument constraints, outbound DLP on tool arguments, human-in-the-loop on irreversible verbs, MCP descriptor pinning, chain detection, taint escalation |
| Memory protection | Guarded reads and writes, poison quarantine, secret redaction, SHA-256 integrity baselines, snapshot and rollback |
| Instruction-file protection | Screening and pinning of SKILL.md, CLAUDE.md, AGENTS.md, and .cursorrules (drift and poisoning detection) |
| Evidence | Append-only signed ledger, SQLite or Postgres mirror, ECS/MITRE SIEM export, signed posture attestation with a computed evidence level |
| Governance | Multi-org tenancy, RBAC (admin/operator/viewer), per-org budgets and cost reporting |
| Control | Four-source kill switch that drills to full deny-all |
| Learning | Human-gated learning loop that ships only signed rule bundles and can never loosen the gate |

## Architecture Overview

Seven layers (L0–L6), operated as four gates, with a control plane physically
segregated from the agent network. Everything fails closed; every decision is
receipted.

| Gate | Layers | Owns |
|---|---|---|
| Edge Gate | L0 + L1 | Egress choke-point, proxy modes, DNS pinning, SSRF controls, MCP/A2A wrapping |
| Content Gate | L2 + L3 | Normalization, injection, DLP/secrets, PII, entropy, rate and budget |
| Action Gate | L4 + L5 | Identity-bound tool policy, argument constraints, chain detection, HITL, taint, memory guard |
| Evidence and Control Gate | L6 + ops | Signed receipts, ledger and mirror, kill switch, RBAC, config validation, dashboard |

### System Architecture

```mermaid
flowchart TB
    subgraph AGENT["Agent runtime (isolated, no direct egress)"]
        A["AI agent / framework"]
    end

    subgraph DATA["Data plane — al-core (the mediator)"]
        direction TB
        L0["L0 Egress firewall — nftables default-deny + boot self-test"]
        L1["L1 Protocol mediation — forward / fetch / reverse / MCP / A2A"]
        L2["L2 Normalization — six-pass evasion folding"]
        L3["L3 Detection — fail-closed Scanner engine"]
        L4["L4 Capability and taint — identity-bound default-deny policy"]
        L5["L5 Memory guard — screen, baseline, rollback"]
        L6["L6 Evidence — signed hash-chained receipts"]
        L0 --> L1 --> L2 --> L3 --> L4 --> L5 --> L6
    end

    subgraph CONTROL["Control plane (segregated network)"]
        POL["Policy store"]
        IDN["Identity registry and RBAC"]
        KILL["Kill switch API"]
        DASH["Evidence dashboard"]
        LEARN["Learning loop"]
    end

    subgraph WORLD["External world"]
        LLM["LLM providers"]
        MCP["MCP servers"]
        WEB["Web and tools"]
        PEER["Other agents"]
    end

    A -->|"only route out"| L0
    L1 --> WORLD
    CONTROL -->|"signed config / hot reload"| DATA
    DATA -->|"events"| CONTROL
    A -. "no route (topology-enforced)" .-> CONTROL
```

### Component Interaction

```mermaid
flowchart LR
    subgraph CLIs["Command-line surfaces"]
        AL["al (core)"]
        VER["al-verify (standalone)"]
        GOV["al-gov (governance)"]
    end

    RT["Runtime (fail-closed boot)"]
    GW["Gateway (proxies)"]
    CG["Content gate (L2/L3)"]
    AG["Action gate (L4/L5)"]
    LED["Signed ledger (JSONL)"]
    MIR["Mirror (SQLite / Postgres)"]
    SIEM["SIEM export (ECS / MITRE)"]
    ATT["Signed posture attestation"]

    AL --> RT
    RT --> GW --> CG --> AG --> LED
    LED --> MIR --> SIEM
    LED --> ATT
    LED --> VER
    ATT --> VER
    GOV --> ATT
    GOV --> MIR
```

### Request Flow

```mermaid
flowchart LR
    A["Agent request"] --> L0["L0 egress"]
    L0 --> L1["L1 mediation"]
    L1 --> L2["L2 normalize"]
    L2 --> L3["L3 detect"]
    L3 -->|"block / crash / timeout"| R1["Signed receipt + deny"]
    L3 -->|"clear"| L4["L4 policy + arg DLP"]
    L4 -->|"deny"| R1
    L4 -->|"allow"| L5["L5 memory guard"]
    L5 --> OUT["Forward to world"]
    OUT --> R2["Signed receipt"]
    L4 -.->|"irreversible verb"| HITL["HITL approval"]
```

### Request Lifecycle

```mermaid
sequenceDiagram
    participant Agent
    participant Edge as Edge Gate (L0/L1)
    participant Content as Content Gate (L2/L3)
    participant Action as Action Gate (L4/L5)
    participant World
    participant Ledger as Signed Ledger (L6)
    participant Human as Operator (HITL)

    Agent->>Edge: request (tool call / fetch / MCP / A2A)
    Edge->>Edge: identity check, SSRF, DNS pin, budget
    Edge->>Content: normalize (6-pass) then scan
    alt scanner block / crash / timeout
        Content-->>Ledger: write receipt (verdict=block)
        Content-->>Agent: deny (fail closed, machine-readable reason)
    else content clear
        Content->>Action: identity-bound policy + arg DLP
        alt irreversible verb
            Action->>Human: approval request
            Human-->>Action: approve or timeout (timeout = deny)
        end
        Action->>World: forward if allowed
        World-->>Action: response (scanned inbound)
        Action-->>Ledger: write receipt (verdict + findings)
        Action-->>Agent: result or redacted result
    end
```

### Evidence Data Flow

```mermaid
flowchart LR
    DEC["Mediated decision"] --> REC["Receipt — JCS canonical, SHA-256 chained, Ed25519 signed"]
    REC --> JSONL["Append-only JSONL ledger (source of truth)"]
    JSONL --> MIR["Query mirror — SQLite WAL or Postgres"]
    MIR --> DASH["Evidence dashboard"]
    JSONL --> EXP["SIEM export — ECS with MITRE tags"]
    JSONL --> ATT["Per-org posture attestation (computed AEL)"]
    JSONL --> VER["al-verify (no runtime dependency)"]
    ATT --> VER
    EXP --> SOC["SOC / SIEM tooling"]
```

## The Evidence Format

Every mediated decision produces a **receipt** — RFC 8785 (JCS) canonicalized,
SHA-256 hash-chained to its predecessor, Ed25519-signed by the mediator. The
specification (`spec/receipt-v1.md`) and JSON Schema are MIT-licensed and published
first, so third parties can produce and verify receipts without this runtime.

```json
{
  "v": 1,
  "seq": 42,
  "ts": "2026-07-10T12:00:00.000Z",
  "actor": "spiffe://acme/agent/claude-code",
  "action": "mcp_tool_call",
  "target": "tool:send_email",
  "verdict": "block",
  "findings": [
    { "scanner": "tool_policy", "rule_id": "policy.default_deny", "severity": "high", "owasp": "ASI03", "mitre": "T1078" }
  ],
  "block_reason": "TOOL_NOT_ALLOWED",
  "policy_hash": "sha256:...",
  "redaction": { "aws-access-key": 1 },
  "prev_hash": "sha256:...",
  "record_hash": "sha256:...",
  "sig": "ed25519:..."
}
```

- **Action vocabulary (closed set):** `http_forward`, `fetch`, `llm_call`,
  `mcp_tool_call`, `mcp_tool_result`, `memory_read`, `memory_write`,
  `skill_load`, `a2a_message`, `config_change`, `killswitch`.
- **Redaction is counts only** — a class-to-count map, never plaintext.
- **Verification is fail-closed:** the verifier recomputes `record_hash`, checks
  the Ed25519 signature, and validates chain contiguity from genesis. Any failure
  is fatal.

Verify a chain with zero trust in this codebase:

```bash
al-verify data/ledger.jsonl --pubkey keys/mediator_ed25519.pub
# -> chain of 11 receipt(s) verified from genesis   OK
```

The same tool verifies a signed **posture attestation** and a signed **rule
bundle**. Evidence portability is not asserted — the release demos verify a chain
in a subprocess where importing the runtime is forced to fail.

## Security Model

```mermaid
flowchart TB
    subgraph UNTRUSTED_IN["Untrusted zone"]
        AGENTRT["Agent runtime — no direct internet, no control route, identity required"]
    end
    subgraph TRUSTED["Trusted mediator"]
        CORE["al-core — fails closed on scanner / config / storage failure"]
    end
    subgraph EXTERNAL["Untrusted external"]
        PROV["LLM providers — scanned both directions"]
        TOOLS["MCP tools — descriptor pinned, responses scanned"]
        PEERS["Other agents (A2A) — mediated and scanned"]
    end
    subgraph PRIV["Privileged control"]
        CTRL["Dashboard, admin API, policy store — control network only, RBAC"]
    end
    subgraph AUDIT["Audit source of truth"]
        EV["JSONL evidence — append-only, hash-chained, signed"]
    end

    AGENTRT -->|"mediated"| CORE
    CORE --> EXTERNAL
    CORE --> EV
    CTRL -->|"signed config"| CORE
    AGENTRT -. "no route" .-> CTRL
```

**Trust boundaries.** The agent runtime is untrusted (no direct internet, no
control-plane route, identity required). al-core is the trusted mediator and
fails closed on any scanner, config, or storage failure. LLM providers, MCP
tools, and peer agents are external and scanned. The dashboard and admin API are
privileged and reachable only on the control network. The JSONL ledger is the
append-only, hash-chained, signed source of truth.

**Security invariants** (each has a test proving it):

1. Fail closed, everywhere. Default deny. The control plane is unreachable from
   the agent network.
2. Keys never live in `.env`. Config is an enforcement boundary, not a
   suggestion. Evidence is append-only and signed.
3. A learned rule can only ever *tighten* the gate — the loader refuses an
   unsigned or tampered rule bundle rather than loading it with a warning.

**What counts as a vulnerability** (see `SECURITY.md`): an agent reaching the
network without passing through the mediator; the control plane reachable from
the agent network; any input that makes a gate fail open; a forged or altered
receipt that still passes `al-verify`; plaintext secrets or PII in the ledger; a
path that loads an unsigned or tampered rule bundle.

## Governance Model

Multi-tenancy, RBAC, budgets, and signed posture attestations are delivered by
the governance layer (`governance/`, CLI `al-gov`). By design, the open core
never imports the governance layer, and there is a test enforcing it — tenant
isolation is enforced in `core/`, so the governance layer can only narrow what a
caller sees, never widen it.

- **Organizations (tenants).** Org slugs match the org in each agent's SPIFFE
  identity (`spiffe://<org>/agent/<name>`).
- **Users and roles.** `admin`, `operator`, `viewer`, plus cross-org fleet
  admins. Tokens are stored hashed and shown once.
- **Posture attestation.** `al-gov attest export <org>` produces a signed
  attestation carrying a **computed** Agent Evidence Level (AEL 0–3). Enforcement
  cannot be claimed from audit mode — the level is derived from evidence, never
  asserted, and is verifiable with `al-verify`.
- **Cost reporting.** `al-gov cost` reports per-virtual-key spend (requests and
  tokens), optionally scoped to an org and priced with a blended rate.

## Standards and Compliance

Compliance mappings are **engineering planning aids, not legal opinions or
certifications**. They are checkable rather than aspirational, because the
product's core output is signed evidence: an auditor verifies any receipt or the
whole ledger with `al-verify`, with no trust in the operator's binary.

| Framework | Document | Coverage summary |
|---|---|---|
| OWASP Agentic Top 10 (2026) | `docs/owasp-mapping.md` | All ten addressed; seven prevented at source (ASI01, ASI02, ASI03, ASI06, ASI07, ASI09, ASI10), three contained via least-agency and hardening (ASI04, ASI05, ASI08) |
| NIST SP 800-53 rev. 5 | `docs/compliance/nist-800-53.md` | Control mapping to shipped mechanisms |
| EU AI Act | `docs/compliance/eu-ai-act.md` | Obligation mapping |
| SOC 2 (Trust Services Criteria) | `docs/compliance/soc2.md` | Criteria mapping |
| MCP threat model | `docs/compliance/mcp-threats.md` | MCP-specific threats |

**MITRE ATT&CK techniques emitted in receipts:** `T1041`, `T1059`, `T1078`,
`T1134`, `T1195`, `T1204`, `T1552` (and `T1552.005`), `T1565`. These are
surfaced by `al export` as `threat.technique.id` (ECS), so a SOC can pivot on the
technique without knowing anything about AgentLighthouse. The list is the emitted
set, not an aspiration.

## Technology Stack

| Area | Components |
|---|---|
| Runtime | Python 3.12+, FastAPI/Starlette, httpx/httpcore, Uvicorn, Typer/Click |
| Configuration and validation | Pydantic v2, pydantic-settings, PyYAML, watchfiles (hot reload) |
| Cryptography | `cryptography` (Ed25519 signing/verify); RFC 8785 JCS canonicalization (stdlib-only reference implementation) |
| Evidence mirror | SQLite (WAL) by default; optional `al-core[postgres]` (psycopg, lazy-imported) for concurrent writers |
| Dashboard | Vite + React + TypeScript, built to static assets; Playwright for e2e (build toolchain only; prebuilt into the image) |
| Build and packaging | uv workspace (members: `core`, `verify`, `governance`), Hatchling, multi-stage Docker |
| Supply chain | SPDX SBOM (syft), cosign keyless signing and attestation |

Reused open-source components are integrated as swappable adapters behind
AgentLighthouse interfaces, version- and hash-pinned; each is attributed in
`NOTICE` at the moment it is introduced.

## Repository Structure

```
core/         the mediator: proxies, scanners, policy engine, receipts, CLI (al)
verify/       standalone receipt verifier (al-verify) — no runtime dependency
governance/   org tenancy, RBAC, budgets, signed attestation (al-gov)
frontend/     fleet dashboard (Vite + React + TS), prebuilt into the image
spec/         the receipt format (receipt-v1.md + JSON Schema)
policies/     default-deny tool policy
configs/      audit / balanced / strict profiles
docs/         architecture, OWASP mapping, demos, rollout, compliance
deployment/   dev-community / mid-size / enterprise guides (Windows + Linux)
manual-tests/ manual verification guides
examples/     tool-response-injection, memory-poison, a2a-lab demos
tests/        automated test suite
```

`governance/` imports `core/`, never the reverse — and there is a test enforcing
it.

## Getting Started

> For the complete, command-by-command walkthrough — installation, the full
> configuration reference, identities and keys, integration modes, evidence
> verification, governance, and troubleshooting — see the
> [Implementation Guide](implementation.md). Every command there has been
> executed and verified. This section is the fast path.

### Prerequisites

- Python 3.12+ and [uv](https://docs.astral.sh/uv/) for the native workflow.
- Docker (with Compose) for the container workflow.
- Node is **not** required to run — the dashboard is prebuilt into the image and
  can be built separately only if you are developing the frontend.

### Get the source

```bash
git clone https://github.com/neural-nomad1709/agentlighthouse.git
cd agentlighthouse
```

### Get the published image (container)

The hardened image — the core plus the prebuilt fleet dashboard, running
non-root — is published to Docker Hub. Pull it by tag, or pin the digest for an
immutable, tamper-evident reference:

```bash
docker pull amitkala/agentlighthouse:v1.0

# immutable digest pin:
docker pull amitkala/agentlighthouse@sha256:313453f3e50895f90140f5a275d1cd7b68cda39a51bcdccf02b8b823ac6c67f6
```

The repository's `docker-compose.yml` references this same image and wraps it in
the full segregated topology (agent-net / egress-net / control-net, the kill
switch, and the two boot probes) — see [Deployment Models](#deployment-models).

### Install and verify (native)

```bash
uv sync                 # install the workspace
uv run al init          # keys, dev .env, data dir, signing key
uv run al healthz       # boot the runtime; verify config + receipt chain
uv run pytest -q        # run the test suite
```

Exercise the gates directly:

```bash
uv run al scan "ignore all previous instructions"        # block INJECTION_BLOCKED (exit 3)
uv run al scan "AKIAIOSFODNN7EXAMPLE"                     # strip aws-access-key      (exit 2)
uv run al policy check spiffe://acme/agent/x exec_shell  # deny TOOL_NOT_ALLOWED     (exit 3)
```

### Run the demos

Each demo is laptop-runnable and ends in independent cryptographic verification.

```bash
make demo          # RELEASE GATE: tool-response injection blocked on all 3 MCP transports (ASI01, ASI02)
make demo-memory   # memory poisoning blocked, tampering detected, rollback restores (ASI06)
make demo-a2a      # agent-card poisoning, rug-pull and session smuggling intercepted (ASI07)
make release       # full suite + all three demos
```

`make demo` is the release gate. If it fails, there is no release. The first demo
is the one worth reading: a hostile MCP server with a clean name and a clean
description hides its payload in the tool *response*. Descriptor pinning passes;
poisoning checks pass; it is blocked anyway, on all three transports.

## Deployment Models

### Deployment topology

```mermaid
flowchart TB
    subgraph AGENTNET["agent-net (internal: true)"]
        SANDBOX["agent workload — HTTPS_PROXY only"]
        ST1["agent-selftest — proves no out-of-band egress"]
        ST2["agent-control-probe — proves no control route"]
    end
    subgraph EGRESSNET["egress-net"]
        WORLD2["LLM providers, MCP servers, web"]
    end
    subgraph CONTROLNET["control-net"]
        CONTROLSVC["al-control — admin API, kill switch, dashboard"]
    end

    CORE2["al-core (mediator) — gateway :8443, forward proxy :8080"]

    SANDBOX -->|":8080 / :8443"| CORE2
    CORE2 --> WORLD2
    CORE2 -->|"read-only ledger + kill-switch sentinel"| CONTROLSVC
    SANDBOX -. "no route" .-> CONTROLNET
```

The network topology **is** the security boundary. Two one-shot probes gate every
`docker compose up`, and the agent workload will not start until both pass: one
proves the agent network has no out-of-band egress, the other proves it has no
route to the control plane. If either fails, nothing starts.

```bash
docker compose up -d
curl http://127.0.0.1:8443/healthz     # data plane: healthy, chain verified
```

Every service runs under a hardened baseline (`no-new-privileges`, `cap_drop
ALL`, read-only root filesystem, `tmpfs /tmp`, pids and memory limits, non-root
uid 10001), pinned by `tests/test_hardening.py`. An optional gVisor runtime
profile is provided in `docker-compose.gvisor.yml`.

### Deployment tiers

| Tier | Users | Tenancy | Runs where | Evidence store |
|---|---|---|---|---|
| Dev / community | up to 2 | single-tenant | workstation or laptop | SQLite |
| Mid-size | up to 10 | single-tenant (multi-org optional) | on-premise or self-managed cloud VM | SQLite (one writer per plane) |
| Enterprise | 10+ | multi-tenant (orgs, RBAC, signed attestation) | on-premise or self-managed private cloud (Linux) | Postgres mirror (concurrent writers) |

Step-by-step guides for Windows and Linux, at all three sizes, are in
`deployment/`.

### Platform reality

- **Linux is the production platform.** Two enforcement properties require it:
  secrets delivered with sane file modes (`/run/secrets`, uid 10001, mode 0400)
  and L0 nftables enforcement on agent hosts.
- **Windows is a first-class development and evaluation platform.** The full
  suite, all three demos, the native gateway, and the Docker Desktop topology run
  on Windows — the dev-community tier.
- **Every tier is self-hosted.** "Cloud" means your own IaaS VMs; there is no
  vendor-hosted SaaS.

### Kubernetes

Kubernetes and Helm manifests are **not shipped** in this repository. Supported
deployment is Docker Compose, native (`uv`), and the probe-gated one-command
pilot install (`make pilot`, or `scripts/pilot-install.ps1` on Windows). The
compose topology (segregated networks, boot probes, hardened baseline) is the
reference for any orchestration you build.

## Configuration and Rollout

Three shipped modes select an enforcement posture, chosen with `--config`
(explicit YAML beats environment variables). The annotated config files, the
environment-variable reference, and the secrets model are in the
[Implementation Guide](implementation.md#3-configuration-reference).

| | audit | balanced (default) | strict |
|---|---|---|---|
| Scan verdicts | observed and receipted, not enforced | enforced | enforced |
| Permissive settings | allowed (only mode) | refused at validation | refused at validation |
| Egress | as configured | default-deny | default-deny, HTTPS only |
| Rate / data budget per domain | as configured | 10 rps / 10 MiB/day | 5 rps / 5 MiB/day |
| Fetch limits | as configured | 5 MiB, 3 redirects | 1 MiB, 1 redirect |
| Attestation level | capped at AEL-1 | AEL-2+ | AEL-2+ |

**Enforced in every mode, including audit:** scanner crash or timeout blocks;
guard-native memory checks; key policy (missing or loose key refuses to start);
signed rules only; the kill switch; and full evidence chaining.

**Promotion path:** audit (1–2 weeks against real workloads) to balanced
(default production posture) to strict (high-sensitivity workloads). Each stage
has a checklist in `docs/rollout.md`, including a signed attestation exported
before and after — the posture change is itself evidence.

## Usage Examples

### Integration Modes

Agents integrate through standard ingress modes, most requiring no agent code
change. Each path is scanned, authorized, and receipted identically.

```mermaid
flowchart LR
    subgraph AGENTS["Agent integration"]
        P1["HTTPS_PROXY -> CONNECT forward proxy"]
        P2["GET /fetch?url="]
        P3["OpenAI /v1/chat/completions (reverse)"]
        P4["Anthropic /v1/messages (reverse)"]
        P5["MCP stdio wrap"]
        P6["MCP Streamable HTTP upstream"]
        P7["A2A envelope mediation"]
    end
    CORE3["al-core mediator — scan, authorize, receipt"]
    EXT["LLM providers, MCP servers, web, peers"]
    P1 --> CORE3
    P2 --> CORE3
    P3 --> CORE3
    P4 --> CORE3
    P5 --> CORE3
    P6 --> CORE3
    P7 --> CORE3
    CORE3 --> EXT
```

### Mediate an MCP server (no agent code change)

```bash
al mcp proxy --actor spiffe://acme/agent/claude-code -- npx some-mcp-server
```

`tools/list` is pinned and poison-scanned; `tools/call` is authorized against the
identity's policy; results are scanned; every decision is receipted.

### Screen and pin agent instruction files

```bash
al skill check ./my-skills/     # recursively screen + pin SKILL.md / CLAUDE.md / .cursorrules
                                # exit 0 clean, 2 redacted, 3 poisoned or drifted
```

### Guard memory operations

```bash
al memory put notes/todo "..."  # screened write; blocked + quarantined if poisoned
al memory verify                # integrity-check protected keys against baselines
al memory rollback              # restore to a known-good snapshot
```

### Export evidence to your SIEM

```bash
al export --verdict block > blocks.ndjson   # ECS/MITRE-tagged, each event carries record_hash + sig
```

## Command Reference

| CLI | Purpose | Representative commands |
|---|---|---|
| `al` | Core data + control plane | `init`, `keygen`, `check`, `scan`, `gateway`, `run`, `dashboard`, `healthz`, `export`, `verify-receipt`, `identity`, `vkey`, `egress`, `policy`, `mcp`, `memory`, `skill`, `killswitch`, `learn`, `db` |
| `al-verify` | Standalone verification (no runtime dependency) | verify a receipt, a JSONL/array chain, a signed rule bundle, or a posture attestation |
| `al-gov` | Multi-org governance | `org`, `user`, `attest`, `cost`, `serve` |

Run any command with `--help` for full options. Exit codes are scriptable
(commonly: 0 allow, 2 strip/redact, 3 block/deny).

## Observability

The control plane serves a read-only **evidence dashboard** (`al dashboard`,
admin-token gated, control network only). It provides:

- A **trace board** for live incident response: a live receipt stream, an alert
  center surfacing every `block` and `ask` with full context (agent, session,
  plane, sequence, rule, signed hash), and receipt detail with in-place
  signature/chain verification.
- A **performance board** for analysis: posture tiles, stacked-bar trends,
  blocked-or-held rate, decision-latency percentiles (p50/p95), and top-N
  breakdowns.

Color discipline is deliberate: a chain that could not be *checked* reads amber
`unverified`, never red `BROKEN` — that word is reserved for tampering.

Beyond the dashboard, observability is evidence-native: the JSONL ledger is the
canonical log, the SQLite/Postgres mirror is the query surface, and SIEM export
carries `record_hash` and `sig` so every alert traces back to a verifiable
receipt.

## Production Readiness

- **Fail-closed by construction.** Scanner crash or timeout blocks; boot is
  fail-closed (a bad config, missing key, or unverifiable chain refuses to
  start); the kill switch drills to deny-all from any of its sources.
- **Reliability and separation.** Each plane owns its own ledger with a single
  writer; the control plane attaches the data plane's mirror read-only, so the
  one-writer-per-chain invariant holds by construction. The chain is re-verified
  on startup.
- **Failure recovery.** Memory snapshot and rollback restore known-good state;
  protected-key integrity baselines catch out-of-band tampering on read; the
  ledger is append-only and tamper-evident.
- **Scalability posture.** SQLite (WAL) suits single-writer plane deployments;
  the optional Postgres mirror is the concurrent-writer path for larger fleets.
- **Honest maturity.** The enforcement gates are real and tested, but they have
  not yet met a production partner workload; false-positive tuning and
  zero-breakage proof require a real pilot. Treat any deployment as a pilot
  posture and read [What This Does Not Do](#what-this-does-not-do).

## CI/CD and Supply-Chain Integrity

```mermaid
flowchart LR
    PUSH["push / pull request"] --> SYNC["uv sync --frozen"]
    SYNC --> TESTS["pytest -q"]
    TESTS --> GATE["release gate: make demo"]
    GATE --> D2["make demo-memory"]
    D2 --> D3["make demo-a2a"]
    PUSH --> IMG["image builds from a clean clone (no push)"]

    REL["GitHub release published"] --> BUILD["build + push to ghcr.io"]
    BUILD --> SIGN["cosign sign (keyless OIDC) — the digest, not the tag"]
    SIGN --> SBOM["attach SPDX SBOM attestation"]
```

- **`ci.yml`** runs on every push and pull request: install, full test suite,
  the release gate (`make demo`, all three MCP transports), the memory and A2A
  demos, and an image-build-from-clean-clone job that proves a clone is
  sufficient to deploy.
- **`publish-image.yml`** runs on a published release: build and push to
  `ghcr.io`, cosign keyless (OIDC) signing of the image **digest**, and an SPDX
  SBOM attestation.

Verify a release:

```bash
cosign verify <image>
cosign verify-attestation --type spdxjson <image>
```

## Enterprise Adoption Guide

**Use cases.** Governing fleets of coding, research, or operations agents;
mediating MCP tool ecosystems; protecting agent memory and instruction files;
producing audit-grade evidence for security reviews and regulators; and
containing the blast radius of a compromised or rogue agent.

**Adoption path.**

1. **Evaluate on a laptop.** Run the suite and the three demos; verify the
   receipts yourself with `al-verify`.
2. **Deploy in audit mode.** Front real agent workloads with the mediator;
   nothing user-visible changes while every would-be verdict is receipted.
3. **Tune from evidence.** Use the dashboard, `al export --verdict block`, and
   `al learn mine` to separate attacks from false positives.
4. **Promote to balanced, then strict** where the data sensitivity warrants it,
   exporting a signed attestation at each step.

**Reference architecture.** A segregated agent network with no out-of-band
egress and no control-plane route; al-core as the sole mediator bridging the
agent network to egress; a control plane hosting policy, RBAC, the kill switch,
and the dashboard; and a signed evidence ledger mirrored for query and exported
to your SIEM.

## Build vs Buy

Building this in-house means owning: a fail-closed mediation proxy across
multiple protocols (HTTP, OpenAI/Anthropic, MCP stdio and HTTP, A2A); a
normalization and detection pipeline resistant to evasion; an identity-bound
policy engine with argument-level DLP and human-in-the-loop; a memory guard with
integrity baselines and rollback; and — hardest of all — a canonicalized,
hash-chained, signed evidence format with a standalone verifier and a
compliance-mapping story. AgentLighthouse provides these as an MIT-licensed,
self-hosted plane with published specifications and no evidence lock-in, so the
build-vs-buy decision is not "adopt a black box" but "adopt a verifiable,
inspectable control plane you can extend."

## Roadmap

Directional and candidate work, drawn from publicly documented gaps. Nothing here
is a dated commitment.

- **Named ML detection engines** (LLM Guard, Presidio) as optional adapters
  behind the existing `Scanner` interface, keeping the default install
  dependency-free.
- **A2A wire transport** (HTTP/gRPC) with **sender authentication** and replay
  protection, graduating the shipped mediator and harness to production
  inter-agent traffic.
- **TLS interception** inside CONNECT tunnels (currently deferred; the forward
  proxy enforces on destination host, port, and pinned IP only).
- **Bare-metal Linux validation** of L0 nftables enforcement.
- **A production pilot** to establish false-positive rate and zero-workflow
  breakage.

## What This Does Not Do

Read this before you trust it in production. This is the master honesty
statement; the compliance mappings defer to it.

- The named ML engines (LLM Guard, Presidio) are **not shipped**. The baseline
  scanners are dependency-free regex and heuristics behind the same `Scanner`
  interface. Of LLM Guard's 24 scanners this covers four fully and four
  partially, and none of the ML-judgement ones. A **detect-secrets adapter**
  ships behind that interface (opt-in: `al-core[scanners]` +
  `scanner.detect_secrets.enabled: true`) — its curated keyword/format
  detectors, not the noisy generic-entropy ones, and it is still pattern
  matching, not ML judgement.
- **A2A sender identity is asserted, not proven** — the mediator pins agent cards
  and binds sessions to their peer pair, but it does not cryptographically verify
  who a peer claims to be.
- **The forward proxy tunnels TLS opaquely.** It enforces on destination host,
  port, and pinned IP; it cannot see inside a CONNECT tunnel, so the content gate
  does not apply there.
- **L0 nftables enforcement** is proven in Docker (`internal: true` networks) and
  by unit tests, but has not been validated on a bare-metal Linux host.
- **Pilot outcomes** — false-positive rate and zero-workflow-breakage — need a
  real partner workload, and this has not had one yet.

## Contributing and Security Reporting

This is a single-maintainer project. There is no separate contribution process
document; open a discussion before substantial changes.

**Security reporting.** Email the maintainer (see `SECURITY.md`) with the version
or commit, the configuration profile (`audit` / `balanced` / `strict`), and the
smallest input that demonstrates the finding. If it produced receipts, attach
them — they are signed, so they are evidence. Please do not open a public issue
for a suspected vulnerability. A gap already documented in
[What This Does Not Do](#what-this-does-not-do) is not a vulnerability report; a
gap that is worse than described very much is.

## Testing

- **711 automated tests** (`uv run pytest -q`): 699 pass in a standard
  environment, with 12 skipped (Postgres-backed mirror tests unless a live-server
  DSN is provided, plus Linux-only nftables/netns and POSIX-mode tests). A 9-test
  Playwright dashboard end-to-end suite lives in `frontend/`.
- The **three demos run as acceptance tests** in the suite, so a demo cannot rot
  silently; `make demo` is the CI release gate.
- Selected tests are gated by platform or backend (Linux-only nftables netns
  tests; Postgres-backed mirror tests).
- Manual verification guides are in `manual-tests/`.

```bash
uv run pytest -q                 # full suite
make release                     # suite + all three demos
make cov                         # coverage report
```

## Versioning

The core package is versioned (`al-core` 0.1.0). Released container images are
tagged with semantic-version and `latest` tags and published to `ghcr.io`, signed
by digest. A formal public versioning and release-cadence policy is not yet
documented; treat the current line as pre-1.0.

## FAQ

**Can I trust the evidence without trusting your code?** Yes. `al-verify` depends
only on `cryptography` and does not import the runtime; the receipt format is a
published MIT-licensed specification.

**Does it require changing my agent?** No — the forward proxy works via standard
`HTTPS_PROXY`, and MCP servers are mediated by wrapping their command. Reverse and
fetch proxies are drop-in for provider and fetch traffic.

**Is there a hosted SaaS?** No. Every tier is self-hosted on infrastructure you
control.

**What does it cost to run?** It is MIT open source; you run it on your own
infrastructure. There are no published benchmark or ROI figures in this
repository — evaluate against your own workload in audit mode.

**Which mode should I start in?** Audit. Collect a week or two of receipted
would-be verdicts, tune, then promote to balanced.

## Glossary

| Term | Meaning |
|---|---|
| Receipt | A mediator-signed, hash-chained record of exactly one mediated decision |
| Chain | The append-only sequence of receipts, verifiable from genesis |
| Gate | An operational grouping of layers (Edge, Content, Action, Evidence/Control) |
| Choke-point | The mediator the agent cannot route around |
| Taint | State marking a session that ingested untrusted content, raising later scrutiny |
| HITL | Human-in-the-loop approval, required on irreversible verbs |
| AEL | Agent Evidence Level (0–3), computed for a signed posture attestation |
| SPIFFE id | Agent identity of the form `spiffe://<org>/agent/<name>` |
| Rug-pull / drift | A previously pinned descriptor or agent card silently changing |
| Fail-closed | On any uncertainty or failure, deny rather than allow |

## License and Attribution

MIT in its entirety — `core/`, `spec/`, `verify/`, `governance/`, and
`frontend/`. See `LICENSE.txt` (also at `license/LICENSE-MIT`). Reused
open-source components are tracked in `NOTICE`. `governance/` stays a separate
layer with a test-enforced dependency direction (it imports `core/`, never the
reverse), but that boundary is architectural, not a licensing split.

Architecture influenced by the OWASP Agentic Top 10 (2026) and OWASP Agent Memory
Guard. This is an independent implementation.

"AgentLighthouse" is a working name.
