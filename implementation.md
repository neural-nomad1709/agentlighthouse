# AgentLighthouse — Implementation Guide

Installation, configuration, and operation of AgentLighthouse — the runtime
security and governance plane for AI agents. This guide takes you from a clean
machine to a running, verified mediator: install, initialize, configure,
integrate your agents, and independently verify the evidence it produces.

Every command in this document was executed and verified on a Windows 11 host
(Docker Desktop, Linux engine) against image
`amitkala/agentlighthouse:v1.0`. Where a command is platform-specific or has a
prerequisite, it is called out inline. See the [Verification matrix](#verification-matrix)
at the end for exactly what was tested and how.

- **Source:** <https://github.com/neural-nomad1709/agentlighthouse>
- **Image:** `docker pull amitkala/agentlighthouse:v1.0`
- **License:** MIT

---

## Contents

- [Prerequisites](#prerequisites)
- [1. Installation](#1-installation)
- [2. Quick start](#2-quick-start)
- [3. Configuration reference](#3-configuration-reference)
- [4. Identities, keys, and budgets](#4-identities-keys-and-budgets)
- [5. Running the planes](#5-running-the-planes)
- [6. Integration modes](#6-integration-modes)
- [7. Evidence and verification](#7-evidence-and-verification)
- [8. Governance (multi-org)](#8-governance-multi-org)
- [9. Validation](#9-validation)
- [10. Platform notes and troubleshooting](#10-platform-notes-and-troubleshooting)
- [Command reference](#command-reference)
- [Verification matrix](#verification-matrix)

---

## Prerequisites

| Tool | Version | Needed for | Install |
|---|---|---|---|
| Python | 3.12+ | Native workflow | `winget install Python.Python.3.12` (Win) / your package manager |
| uv | latest | Native workflow (deps + runner) | `winget install astral-sh.uv` (Win) / `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Git | any | Cloning the repo | `winget install Git.Git` |
| Docker | with Compose | Container workflow | Docker Desktop (Win/macOS) / Docker Engine + compose plugin (Linux) |
| Node.js | 20+ | Only to build the dashboard *from source* | Not required for the container path — the image ships the dashboard prebuilt |

Node is **not** required to run AgentLighthouse. `make` is **not** required (and
is absent on a default Windows install) — every task has a `uv run` equivalent
shown below.

---

## 1. Installation

### 1.1 Native (uv) — recommended for evaluation and development

```bash
git clone https://github.com/neural-nomad1709/agentlighthouse.git
cd agentlighthouse
uv sync
```

`uv sync` resolves and installs the workspace (`al-core`, `al-verify`,
`al-governance`) into a local `.venv`. All CLI entry points then run through
`uv run`: `al`, `al-verify`, `al-gov`.

### 1.2 Container (Docker Hub)

Pull the hardened image — the core plus the prebuilt fleet dashboard, running
non-root. Pull by tag, or pin the digest for an immutable, tamper-evident
reference:

```bash
docker pull amitkala/agentlighthouse:v1.0

# immutable digest pin:
docker pull amitkala/agentlighthouse@sha256:313453f3e50895f90140f5a275d1cd7b68cda39a51bcdccf02b8b823ac6c67f6
```

> The image is **fail-closed**: a bare `docker run` refuses to start without an
> admin API token (`error: refusing to start ... admin_api_token Field
> required`). This is intended. Run the container through Docker Compose
> (§[5.3](#53-full-topology-docker-compose)), which supplies the token as a
> secret and wires the segregated network topology.

---

## 2. Quick start

The native path, from a fresh clone to independently verified evidence:

```bash
uv run al init --config configs/balanced.yaml     # keys/, data/, .env (dev admin token)
uv run al healthz --config configs/balanced.yaml  # boot the runtime; verify config + receipt chain
uv run al scan "ignore all previous instructions" # a prompt-injection payload
uv run al-verify data/ledger.jsonl --pubkey keys/mediator_ed25519.pub
```

`al init` writes a dev `.env`, generates the Ed25519 signing key at
`keys/mediator_ed25519` (mode 0600), and creates `data/`. `al scan` prints the
verdict and findings and sets an **exit code** you can gate on:

| Input | Verdict | Exit code |
|---|---|---|
| `"ignore all previous instructions"` | `block` (INJECTION_BLOCKED) | `3` |
| `"AKIAIOSFODNN7EXAMPLE"` | `strip` (secret redacted in flight) | `2` |
| benign text | `allow` | `0` |

```bash
uv run al scan "AKIAIOSFODNN7EXAMPLE"                     # -> strip (exit 2)
uv run al policy check spiffe://acme/agent/x exec_shell   # -> deny TOOL_NOT_ALLOWED (exit 3)
```

---

## 3. Configuration reference

Configuration is a YAML file selected with `--config`. Three profiles ship in
`configs/`. Secrets never live in these files — see [3.4](#34-secrets-never-in-yaml).

### 3.1 Profiles

| Profile | File | Posture |
|---|---|---|
| `audit` | `configs/audit.yaml` | Observe and record; do not break workflows. The **only** profile where a protection may be disabled (to tune false positives). Never run in production. |
| `balanced` | `configs/balanced.yaml` | **Default.** Protections on; block-wins verdict precedence. Per-domain 10 rps, 5 MiB fetch cap, 3 redirects. |
| `strict` | `configs/strict.yaml` | Tightest thresholds. HTTPS only (port 443), 1 MiB fetch cap, 1 redirect, 5 rps. No permissive settings allowed. |

Validate any profile before using it (fail-closed — non-zero exit on any error):

```bash
uv run al check --config configs/audit.yaml
uv run al check --config configs/balanced.yaml
uv run al check --config configs/strict.yaml
```

### 3.2 `configs/*.yaml` — annotated

The `balanced` profile, with every key explained:

```yaml
mode: balanced            # audit | balanced | strict
env: dev                  # dev | prod (prod enforces L0 egress self-test)
listen: "0.0.0.0:8888"    # control-plane bind address
scanner:
  dlp:
    enabled: true         # outbound DLP: redact secrets/PII in flight
  ssrf:
    block_private: true       # deny requests to private/link-local ranges
    dns_rebind_protection: true
  entropy:
    path_threshold: 4.0       # high-entropy path/subdomain detection (exfil)
    subdomain_threshold: 3.5
  rate_limit:
    per_domain_rps: 10        # per-destination request rate cap
  data_budget:
    per_domain_bytes: 10485760  # per-destination data cap (10 MiB)
  url_max_len: 8192
gateway:
  allow_hosts: []             # DEFAULT-DENY. Agents reach ONLY listed hosts.
                              #   "*.example.com" matches subdomains.
  allow_ports: [80, 443]
  require_identity: true      # every request must carry a valid agent identity
  fetch_max_bytes: 5242880    # 5 MiB response cap
  max_redirects: 3
  request_timeout_s: 30.0
  pin_ttl_s: 300.0            # DNS pin TTL (anti-rebind)
egress:
  bypass_self_test: auto      # auto = enforced when env: prod
  probe_targets: ["1.1.1.1:443", "8.8.8.8:53"]
  probe_timeout_s: 3.0
```

The single most important knob is `gateway.allow_hosts`: an empty list is
default-deny — your agents reach nothing until you add hosts deliberately.

### 3.3 Environment variables

Environment variables override file defaults; explicit YAML beats env. Nested
keys use `__` (double underscore).

| Variable | Purpose |
|---|---|
| `AL_ENV` | `dev` or `prod` |
| `AL_MODE` | `audit` / `balanced` / `strict` |
| `AL_ADMIN_API_TOKEN` | Admin API token (control plane). Required to boot the control plane. |
| `AL_KEYS__SIGNING_KEY_PATH` | Path to the Ed25519 signing key |
| `AL_GATEWAY__FORWARD_LISTEN` | Bind address for the CONNECT forward proxy (default `127.0.0.1:8080`) |
| `AL_GATEWAY__UPSTREAM__OPENAI_API_KEY` | Upstream OpenAI key (never in YAML) |
| `AL_GATEWAY__UPSTREAM__ANTHROPIC_API_KEY` | Upstream Anthropic key (never in YAML) |
| `AL_CONTROL__KILLSWITCH_DIR` | Directory holding the kill-switch sentinel file |

Setting an env var:

```bash
# Linux / macOS
export AL_GATEWAY__UPSTREAM__ANTHROPIC_API_KEY="sk-ant-..."

# Windows PowerShell
$env:AL_GATEWAY__UPSTREAM__ANTHROPIC_API_KEY = "sk-ant-..."
```

### 3.4 Secrets (never in YAML)

| Secret | Native location | Container |
|---|---|---|
| Admin API token | `.env` (`AL_ADMIN_API_TOKEN`) or `keys/admin_api_token` | Compose secret `al_admin_api_token` |
| Mediator signing key | `keys/mediator_ed25519` (0600) | Auto-generated on the data volume, or mounted as a secret in prod |
| Upstream provider keys | `AL_GATEWAY__UPSTREAM__*` env only | Same, via `env_file` (not committed) |

The signing key is the root of evidence trust — back up `keys/` and never commit
it (the repo `.gitignore` already excludes it).

---

## 4. Identities, keys, and budgets

Every agent has a SPIFFE-style identity; every user can have a virtual LLM key
with request/token budgets. Tokens are shown **once** and stored hashed.

```bash
# issue an agent identity: al identity issue <org> <agent-name>
uv run al identity issue home alice-agent
#   -> spiffe://home/agent/alice-agent  + a bearer token (store now)

# issue a per-user virtual LLM key with daily budgets
uv run al vkey issue alice --max-requests 200 --max-tokens 200000
#   -> alk_...  virtual key (store now)

# rotate the mediator signing key (dev)
uv run al keygen --force
```

---

## 5. Running the planes

### 5.1 Data-plane gateway

The gateway is the agent-facing choke-point: fetch proxy + reverse proxy on
`:8443`, CONNECT forward proxy on `:8080`.

```bash
uv run al gateway --host 127.0.0.1 --config configs/balanced.yaml
# health: GET http://127.0.0.1:8443/healthz
# override the port with --port if 8443 is taken
```

### 5.2 Control plane and evidence dashboard

```bash
uv run al run --config configs/balanced.yaml   # control-plane API (/healthz)
```

The dashboard is a read-only view of the evidence ledger. Give it its **own**
data dir and attach the gateway's dir read-only — never point two writers at one
hash chain:

```bash
# native: build the dashboard once (needs Node 20+), then serve it
npm --prefix frontend install
npm --prefix frontend run build
uv run al dashboard --data-dir data/control \
                    --dataplane-dir data \
                    --dataplane-pubkey keys/mediator_ed25519.pub
# -> http://127.0.0.1:8899/dashboard/  (admin token from .env)
```

The container image ships the dashboard prebuilt, so the Node build step is not
needed on the container path.

### 5.3 Full topology (Docker Compose)

The compose stack wraps the image in the sealed three-network topology
(agent-net / egress-net / control-net) with a kill switch and two one-shot boot
probes that must pass before the agent sandbox is allowed to start.

```bash
docker compose config      # validate the topology (no changes)
docker compose up -d        # bring the stack up
docker compose ps           # al-core should be "healthy"; probes exit 0
docker compose down -v      # tear down and remove volumes
```

Verified bring-up state:

```
al-core               running (healthy)
al-control            running          # control port -> 127.0.0.1:8898
agent-selftest        exited (0)        # proves no out-of-band egress
agent-control-probe   exited (0)        # proves no control-net route from agents
```

Data-plane health after `up`: `curl http://127.0.0.1:8443/healthz` returns
`{"status":"healthy",...,"chain":{"verified":true,...}}`.

---

## 6. Integration modes

Point your agent at the gateway; no agent code change is required for the proxy
paths.

| Traffic | How to route it |
|---|---|
| LLM API | Base URL `http://127.0.0.1:8443/v1`, API key = the `alk_` virtual key |
| Web / tool egress | `HTTPS_PROXY=http://127.0.0.1:8080` with proxy credentials `spiffe-id:token`, or `GET /fetch?url=` with identity headers |
| MCP server | `uv run al mcp proxy --actor <spiffe-id> -- <server command>` |

---

## 7. Evidence and verification

Every mediated decision is an Ed25519-signed, hash-chained receipt. Export to
your SIEM, and verify the chain with the standalone verifier (no `al-core`
import needed).

```bash
# SIEM export: newline-delimited JSON, ECS + MITRE tags, each event signed
uv run al export --verdict block > blocks.ndjson

# independent verification of the whole ledger
uv run al-verify data/ledger.jsonl --pubkey keys/mediator_ed25519.pub
# -> chain of N receipt(s) verified from genesis / OK
```

---

## 8. Governance (multi-org)

The governance layer (`al-gov`) adds org tenancy, RBAC, budgets, and signed
posture attestation. It runs on the control host and builds on the core.

```bash
uv run al-gov org create acme                                  # create a tenant
uv run al-gov org list
uv run al-gov user add alice@acme --org acme --role admin      # role: admin|operator|viewer
uv run al-gov user list

# signed, independently verifiable posture attestation
uv run al-gov attest export acme > acme.attest.json
uv run al-gov attest verify acme.attest.json                   # -> verified (AEL-n) / OK

uv run al-gov cost --org acme                                  # today's spend per virtual key
uv run al-gov serve                                            # governed control plane + dashboard
```

---

## 9. Validation

Prove the install. The three demos are laptop-runnable and each ends in
independent cryptographic verification; the first is the release gate.

```bash
uv run pytest -q                                          # full test suite

uv run python examples/tool-response-injection/demo.py    # RELEASE GATE (ASI01/ASI02)
uv run python examples/memory-poison/demo.py              # memory poisoning + rollback (ASI06)
uv run python examples/a2a-lab/demo.py                    # A2A card poisoning + smuggling (ASI07)
```

> The `Makefile` targets `make demo`, `make release`, etc. are convenience
> wrappers for the commands above. `make` is not installed on a default Windows
> host — use the `uv run python examples/...` commands directly, which are
> exactly what the Make targets call.

---

## 10. Platform notes and troubleshooting

- **`make` not found (Windows).** Expected. Use the `uv run` equivalents in
  [§9](#9-validation) and the `Makefile` as a reference for what each target runs.
- **Bare `docker run` exits immediately.** The image is fail-closed and requires
  the admin token. Use `docker compose up` (§[5.3](#53-full-topology-docker-compose)),
  which provides it as a secret.
- **Port 8443 already in use.** Another gateway/stack is running. Stop it
  (`docker compose down`) or pass `al gateway --port <free-port>`.
- **L0 egress (Linux only).** Render the nftables default-deny ruleset anywhere;
  apply it only inside an isolated agent network namespace on Linux as root:
  ```bash
  uv run al egress nftables --al-core-ip 10.0.0.2            # render (prints ruleset)
  uv run al egress nftables --al-core-ip 10.0.0.2 --apply    # apply (Linux, root)
  ```
- **Dashboard "unverified" chain.** Pass `--dataplane-pubkey keys/mediator_ed25519.pub`
  so the dashboard can verify the gateway's chain rather than only display it.
- **Windows Docker secrets.** A Windows host cannot deliver `/run/secrets` with
  strict modes; the dev compose stack auto-generates the signing key on the
  Linux-native volume, which is correct for the dev tier.

---

## Command reference

| Command | What it does |
|---|---|
| `uv run al version` | Print the al-core version |
| `uv run al init --config <cfg>` | Initialize keys/, data/, .env |
| `uv run al keygen [--force]` | Generate / rotate the signing key |
| `uv run al check --config <cfg>` | Validate config (fail-closed) |
| `uv run al healthz --config <cfg>` | Boot runtime; verify config + chain |
| `uv run al scan "<text>"` | Run the content gate; exit 3 block / 2 strip / 0 allow |
| `uv run al policy check <spiffe-id> <tool>` | Check identity-bound tool policy |
| `uv run al identity issue <org> <agent>` | Issue an agent identity + token |
| `uv run al vkey issue <user> --max-requests N --max-tokens M` | Issue a virtual LLM key with budgets |
| `uv run al gateway --config <cfg> [--port N]` | Run the data-plane gateway |
| `uv run al run --config <cfg>` | Run the control-plane API |
| `uv run al dashboard --data-dir ... --dataplane-dir ... --dataplane-pubkey ...` | Serve the evidence dashboard |
| `uv run al export --verdict block` | Export the ledger as SIEM NDJSON |
| `uv run al egress nftables --al-core-ip <ip> [--apply]` | Render / apply L0 egress ruleset (Linux) |
| `uv run al-verify <ledger> --pubkey <pub>` | Independently verify the receipt chain |
| `uv run al-gov org create <slug>` | Create a tenant |
| `uv run al-gov user add <subject> --org <slug> --role <role>` | Add a user |
| `uv run al-gov attest export <slug>` | Export a signed posture attestation |
| `uv run al-gov attest verify <file>` | Verify an attestation |
| `uv run al-gov cost --org <slug>` | Per-key spend for an org |
| `docker pull amitkala/agentlighthouse:v1.0` | Download the published image |
| `docker compose up -d` / `down -v` | Bring the sealed topology up / down |

---

## Verification matrix

Every command family below was executed during authoring. "Verified" = run with
the expected result. Constraints are stated where a command is
platform-specific or environment-dependent.

| Command / family | Result |
|---|---|
| `uv --version`, `uv sync` | Verified — uv 0.11.20; workspace resolves (47 packages) |
| `uv run al version` / `--help` | Verified — `al-core 0.1.0` |
| `uv run al check` (audit, balanced, strict) | Verified — all three OK |
| `uv run al scan` (block / strip / allow) | Verified — exit 3 / 2 / 0 respectively |
| `uv run al policy check ... exec_shell` | Verified — `deny TOOL_NOT_ALLOWED` (exit 3) |
| `uv run al init` | Verified — writes `.env`, `keys/` (0600), `data/` |
| `uv run al keygen --force` | Verified — rotates key |
| `uv run al healthz` | Verified — boots; `chain.verified = true` |
| `uv run al identity issue` | Verified — issues `spiffe://...` + token |
| `uv run al vkey issue` | Verified — issues `alk_...` with budgets |
| `uv run al gateway` | Verified — serves `/healthz` 200 (tested on a free port) |
| `uv run al export --verdict block` | Verified — emits ECS/MITRE NDJSON |
| `uv run al-verify <ledger>` | Verified — `chain of 11 receipt(s) verified ... OK` |
| `uv run al-gov org/user/attest/cost` | Verified — create, add, export+verify (AEL-2), cost |
| `uv run python examples/tool-response-injection/demo.py` | Verified — `RELEASE GATE PASSED` (exit 0) |
| `uv run al egress nftables --al-core-ip <ip>` | Verified (render). `--apply` requires Linux + root (not run here) |
| `docker pull amitkala/agentlighthouse:v1.0` | Verified — digest `313453f3…c67f6`, reachable |
| `docker compose config` | Verified — topology valid |
| `docker compose up -d` / `down -v` | Verified — al-core healthy, both probes exit 0, teardown clean |
| bare `docker run <image>` | Verified fail-closed — refuses without admin token (use Compose) |
| `git clone https://github.com/neural-nomad1709/agentlighthouse.git` | Pending the repo push — URL is the published source; clone works once the repo is public |
| `npm --prefix frontend run build` (dashboard, native) | Node 20+ present; the container ships the dashboard prebuilt |
| `make ...` | Not applicable on Windows (no `make`); use the `uv run` equivalents |
