# agentlighthouse-core

**The runtime security and governance plane for AI agents.**

AgentLighthouse is a mediator that sits *outside* the agent. Every network
call, tool call, memory operation and inter-agent message goes through it. It
screens what comes in, authorizes what goes out, and writes a **signed,
hash-chained, independently verifiable receipt** for every decision it takes.

`agentlighthouse-core` is the mediator itself: the proxies, the scanners, the
policy engine, the evidence ledger and the `al` command line.

- **Source and full documentation:** <https://github.com/neural-nomad1709/agentlighthouse>
- **License:** MIT
- **Python:** 3.12 or newer

## Contents

- [Why a mediator](#why-a-mediator)
- [Install](#install)
- [Quick start](#quick-start)
- [What it does](#what-it-does)
- [Architecture](#architecture)
- [Putting an agent behind it](#putting-an-agent-behind-it)
- [Evidence](#evidence)
- [Configuration](#configuration)
- [Command reference](#command-reference)
- [Running in production](#running-in-production)
- [Related packages](#related-packages)
- [Scope and limitations](#scope-and-limitations)
- [Security reporting](#security-reporting)
- [License](#license)

## Why a mediator

An AI agent reads untrusted text (a web page, a tool response, another agent's
message) and then acts on it: it calls tools, writes memory and sends data
out. A guardrail placed inside the agent shares the agent's trust boundary, so
a successful prompt injection is already past it.

AgentLighthouse takes the control point out of the agent. The agent talks to
the mediator, and the mediator decides. Three properties follow:

- **A choke-point.** In the container topology the agent has no other road
  out.
- **Identity-bound least privilege.** Every agent has an identity, and a tool
  runs only when that identity is explicitly allowed to run it.
- **Evidence an auditor can check.** Each decision is an Ed25519-signed
  receipt, chained to the one before it. Anyone can verify the chain with a
  standalone tool that does not import this package.

Everything fails closed: a scanner crash, a timeout, a bad configuration or an
unverifiable ledger denies the request or refuses to start.

## Install

```bash
pip install agentlighthouse-core
```

This installs two commands: `al` (this package) and `al-verify` (the
standalone verifier, from
[agentlighthouse-verify](https://pypi.org/project/agentlighthouse-verify/)).

The wheel carries the shipped configuration profiles, the default-deny tool
policy and the prebuilt evidence dashboard. No source checkout and no Node
toolchain are needed.

Optional extras:

| Extra | Adds |
|---|---|
| `agentlighthouse-core[postgres]` | The Postgres evidence mirror, for several mediators writing to one query surface |
| `agentlighthouse-core[scanners]` | A `detect-secrets` adapter behind the scanner interface |

## Quick start

From an empty directory to independently verified evidence:

```bash
al init                                        # keys/, data/, .env, configs/, policies/
al healthz --config configs/balanced.yaml      # boot the runtime, verify config and chain
al-verify data/ledger.jsonl --pubkey keys/mediator_ed25519.pub
```

`al init` generates the Ed25519 signing key, writes a development `.env`, and
lays down the shipped `configs/` and `policies/` when they are absent. It
never overwrites a file you already have.

Exercise the gates directly. The exit code is scriptable:

```bash
al scan "ignore all previous instructions"         # block  INJECTION_BLOCKED   exit 3
al scan "AKIAIOSFODNN7EXAMPLE"                     # strip  aws-access-key      exit 2
al policy check spiffe://acme/agent/x exec_shell   # deny   TOOL_NOT_ALLOWED    exit 3
```

| Verdict | Meaning | Exit code |
|---|---|---|
| `allow` | Nothing found | `0` |
| `strip` | A secret or PII was found and is redacted in flight | `2` |
| `block` | The content or the action is denied | `3` |

## What it does

| Domain | Capability |
|---|---|
| Network mediation | CONNECT forward proxy, fetch proxy, OpenAI- and Anthropic-compatible reverse proxy with SSE, MCP proxy (stdio and Streamable HTTP), A2A mediation |
| Egress control | Default-deny nftables ruleset, with a boot self-test that refuses to start if out-of-band egress succeeds |
| Content inspection | Six-pass normalization that folds evasions, then a fail-closed detection engine: injection, secrets, PII, SSRF, entropy, BIP-39 seed phrases, rate and data budgets |
| Capability control | Identity-bound default-deny tool policy with argument constraints, outbound DLP on tool arguments, human approval on irreversible verbs, MCP descriptor pinning, chain detection, taint escalation |
| Memory protection | Guarded reads and writes, poison quarantine, secret redaction, SHA-256 integrity baselines, snapshot and rollback |
| Instruction-file protection | Screening and pinning of `SKILL.md`, `CLAUDE.md`, `AGENTS.md` and `.cursorrules` |
| Evidence | Append-only signed ledger, SQLite or Postgres mirror, ECS/MITRE SIEM export |
| Control | A kill switch with four independent sources that drills to full deny-all |
| Learning | A human-gated loop that ships only signed rule bundles and can only tighten the gate |

## Architecture

Seven layers, operated as four gates. The control plane is segregated from the
agent network.

| Gate | Layers | Owns |
|---|---|---|
| Edge Gate | L0 + L1 | Egress choke-point, proxy modes, DNS pinning, SSRF controls, MCP and A2A wrapping |
| Content Gate | L2 + L3 | Normalization, injection, DLP and secrets, PII, entropy, rate and budget |
| Action Gate | L4 + L5 | Identity-bound tool policy, argument constraints, chain detection, human approval, taint, memory guard |
| Evidence and Control Gate | L6 + operations | Signed receipts, ledger and mirror, kill switch, RBAC, configuration validation, dashboard |

A request passes the layers in order:

```
agent -> L0 egress -> L1 mediation -> L2 normalize -> L3 detect
      -> L4 policy -> L5 memory guard -> world
                                      -> L6 signed receipt (every path, allow or deny)
```

The full design is in the
[architecture document](https://github.com/neural-nomad1709/agentlighthouse/blob/main/docs/architecture.md).

## Putting an agent behind it

Most paths need no change to the agent's code.

| Traffic | How to route it |
|---|---|
| LLM API calls | Point the client's base URL at the gateway (`http://127.0.0.1:8443/v1`) and use a virtual key as the API key |
| Web and tool egress | Set `HTTPS_PROXY=http://127.0.0.1:8080` with the agent's identity as proxy credentials, or call `GET /fetch?url=` |
| An MCP server | Wrap its command: `al mcp proxy --actor <spiffe-id> -- <server command>` |

Issue an agent identity and a virtual LLM key, then start the gateway:

```bash
al identity issue acme research-agent      # spiffe://acme/agent/research-agent + a token, shown once
al vkey issue alice --max-requests 200 --max-tokens 200000
al gateway --host 127.0.0.1 --config configs/balanced.yaml
```

The gateway serves the fetch and reverse proxies on port 8443 and the CONNECT
forward proxy on port 8080. Agents reach only the hosts you list under
`gateway.allow_hosts`; an empty list denies everything.

Mediating an MCP server:

```bash
al mcp proxy --actor spiffe://acme/agent/research-agent -- npx some-mcp-server
```

The tool catalog is pinned and scanned for poisoning. Each tool call is
authorized against the identity's policy, and only for a tool the agent was
actually shown. Every server reply is scanned before the agent sees it. Every
decision is receipted.

Other surfaces:

```bash
al skill check ./my-skills/        # screen and pin agent instruction files
al memory put notes/todo "..."     # screened write; a poisoned value is blocked and quarantined
al memory verify                   # check protected keys against their integrity baselines
al memory rollback                 # restore the last known-good snapshot
al killswitch engage               # deny everything, at every ingress
```

## Evidence

Every mediated decision produces a receipt: canonicalized with RFC 8785 (JCS),
SHA-256 chained to its predecessor, and signed with the mediator's Ed25519
key.

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

- Redaction is recorded as a class-to-count map. Plaintext never reaches the
  ledger.
- The append-only JSONL ledger is the source of truth. The SQLite or Postgres
  mirror is a query surface built from it.
- `al export --verdict block` writes ECS-shaped events with MITRE ATT&CK
  technique tags for a SIEM. Each event carries the receipt's `record_hash`
  and `sig`, so an alert traces back to a receipt that can be verified.

The receipt format is a published specification:
[receipt-v1](https://github.com/neural-nomad1709/agentlighthouse/blob/main/spec/receipt-v1.md).

## Configuration

Configuration is a YAML file chosen with `--config`. Three profiles ship in
the wheel and are written to `configs/` by `al init`.

| | `audit` | `balanced` (default) | `strict` |
|---|---|---|---|
| Scan verdicts | Observed and receipted, not enforced | Enforced | Enforced |
| Permissive settings | Allowed (the only mode that allows them) | Refused at validation | Refused at validation |
| Egress | As configured | Default-deny | Default-deny, HTTPS only |

Enforced in every mode, including `audit`: a scanner crash or timeout blocks,
the memory guard's own checks, the key policy, signed rules only, the kill
switch, and full evidence chaining.

Validate a profile before using it:

```bash
al check --config configs/strict.yaml
```

Secrets never live in YAML. The admin token, the signing key and upstream
provider keys come from the environment or from mounted secrets. Environment
variables use the `AL_` prefix, with `__` between nested keys, for example
`AL_GATEWAY__UPSTREAM__ANTHROPIC_API_KEY`.

The annotated configuration reference is in the
[implementation guide](https://github.com/neural-nomad1709/agentlighthouse/blob/main/implementation.md).

## Command reference

| Command | Purpose |
|---|---|
| `al init` | Create a workspace: keys, data directory, `.env`, configs and policy |
| `al check` | Validate configuration; exits non-zero on any error |
| `al healthz` | Boot the runtime and print the health payload |
| `al scan` | Run the content gate over text and print the verdict |
| `al gateway` | Run the data-plane gateway |
| `al run` | Run the control-plane API |
| `al dashboard` | Serve the read-only evidence dashboard |
| `al identity` | Issue, list and revoke agent identities |
| `al vkey` | Issue, list and revoke virtual LLM keys with budgets |
| `al policy` | Inspect and check the identity-bound tool policy |
| `al mcp` | Mediate an MCP server; review its advertised tools |
| `al memory` | Guarded memory reads and writes, snapshot and rollback |
| `al skill` | Screen and pin agent instruction files |
| `al hitl` | List and resolve pending human approvals |
| `al killswitch` | Engage or disengage full deny-all |
| `al export` | Export the ledger as SIEM events |
| `al verify-receipt` | Verify a receipt or a ledger |
| `al egress` | The egress bypass self-test and the nftables ruleset |
| `al learn` | Mine candidate rules, approve and sign them, generate tests |
| `al db` | Initialize and query the evidence mirror |
| `al keygen` | Generate or rotate the signing key |

Run any command with `--help` for its options.

## Running in production

A process started with `al gateway` on a workstation mediates and receipts
what agents send through it, and nothing at the operating-system level stops
an agent from going around it. The mediator says so: startup logs `advisory
mode`, and the signed boot receipt carries the finding
`egress.advisory_mode`.

Enforcement comes from the container topology. The repository ships a hardened
container image and a Docker Compose file that places the agent on a network
whose only route out is the mediator, keeps the control plane on a separate
network, and runs two boot probes that must pass before any agent starts.

- **Image:** `ghcr.io/neural-nomad1709/agentlighthouse`, signed with cosign,
  with an SBOM attestation
- **Deployment guides:**
  [deployment](https://github.com/neural-nomad1709/agentlighthouse/tree/main/deployment)
- **Rollout from audit to strict:**
  [rollout guide](https://github.com/neural-nomad1709/agentlighthouse/blob/main/docs/rollout.md)

## Related packages

| Package | What it is |
|---|---|
| [agentlighthouse-verify](https://pypi.org/project/agentlighthouse-verify/) | The standalone receipt verifier. Its only dependency is `cryptography`. Installed with this package. |
| [agentlighthouse-governance](https://pypi.org/project/agentlighthouse-governance/) | Organizations, role-based access, budgets and signed posture attestation, on top of this package. |

## Scope and limitations

Read this before relying on the mediator.

- The detection engine is pattern matching and heuristics behind a scanner
  interface. It makes no machine-learning judgement.
- The forward proxy tunnels TLS opaquely. It enforces on destination host,
  port and pinned IP address, and does not inspect content inside a CONNECT
  tunnel.
- The identity of an A2A peer is asserted, not cryptographically proven. The
  mediator pins agent cards and binds sessions to their peer pair.
- Outside the container topology the mediator is advisory, as described under
  [Running in production](#running-in-production).

The complete statement is in the repository's
[README](https://github.com/neural-nomad1709/agentlighthouse#what-this-does-not-do).

## Security reporting

Please do not open a public issue for a suspected vulnerability. The reporting
process is in
[SECURITY.md](https://github.com/neural-nomad1709/agentlighthouse/blob/main/SECURITY.md).

## License

MIT. See the `LICENSE` file shipped with this package.
