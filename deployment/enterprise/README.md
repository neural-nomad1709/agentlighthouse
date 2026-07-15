# Deployment: enterprise (10+ users, multiple teams or tenants)

**Profile:** an organization mediating many agents for multiple teams — or a
platform operator serving multiple customer organizations. **Multi-tenant:**
orgs, roles (admin/operator/viewer), org-scoped evidence enforced in the
core, per-org budgets, and signed per-org posture attestations (the
`governance/` layer). **On-premise or self-managed
private cloud** (your VMs, your network — no vendor-hosted service exists).
**Linux only** for the enforcement hosts. Evidence mirror on **Postgres**,
which makes budget check-and-increment atomic across concurrent writers
(proven: 16 writers racing a budget of 100 admit exactly 100).

This tier builds ON the [mid-size](../mid-size/README.md) deployment — do
that guide first; every step here is additive.

## Honest constraints before you commit

- Hardening, compliance mappings, SBOM and signed images are in place, but
  none of it has met a real partner workload yet; run this as a
  design-partner posture with your own review.
- The container image ships the core only; the governed control plane
  (`al-gov serve`) runs natively on the control host today (step 4).
- A2A mediation is an interface + tested mediator, not yet a wire transport;
  MCP HTTP upstreams handle JSON replies, not SSE streams (the README's
  "What this does NOT do" section has the full list).
- Multiple `al-core` replicas share Postgres for budgets and queries, but
  each replica keeps its own signed JSONL chain (one writer per chain, by
  design) — evidence federation across chains is a dashboard concern. The
  dashboard federates on the **read** side: it attaches another plane's ledger
  read-only and merges plane-tagged receipts, verifying each chain separately
  (`core/al_core/audit/pool.py`). Config exposes one such plane today
  (`control.dataplane_dir`); federating N replicas is the same mechanism with a
  longer list, and is not yet wired.

## Linux deployment

### 1. Base

Complete the mid-size Linux guide on your mediation host(s): compose
topology up, probes green, production key delivery via secrets, allowlists
and tool policy configured.

### 2. Postgres evidence mirror

1. Provision Postgres 16+ (your HA/backup standards apply — this is your
   audit trail). Create a database and a dedicated role for AgentLighthouse.
2. Point the runtime at it — backend in config, DSN only via environment
   (it is a SecretStr; a `postgres` backend without a DSN refuses to boot):

   ```yaml
   # configs/balanced.yaml (or your site copy)
   audit:
     backend: postgres
   ```

   ```bash
   # in al-core's environment (compose env_file, not committed)
   AL_AUDIT__DSN=postgresql://al:<password>@db.internal:5432/agentlighthouse
   ```

3. Restart the stack and confirm `/healthz` is healthy. Validate the
   concurrency claim against YOUR server before go-live:

   ```bash
   AL_TEST_POSTGRES_DSN=<same dsn> uv run pytest tests/test_postgres_mirror.py -q   # expect 9 passed
   ```

### 3. Tenants, people, and keys

On the control host (`uv sync` gives you `al-gov`):

```bash
uv run al-gov org create acme                 # one per tenant
uv run al-gov org create globex
uv run al-gov user add op@acme --org acme --role operator     # token shown ONCE
uv run al-gov user add admin@acme --org acme --role admin
uv run al-gov user add secops@you --fleet --role admin        # cross-org fleet admin
```

Issue every virtual key org-scoped — an org-less key's receipts land in the
`system` bucket only a fleet admin can see:

```bash
uv run al vkey issue alice --org acme --max-requests 1000 --max-tokens 1000000
```

Agent identities carry the org in their SPIFFE id
(`al identity issue acme build-agent` -> `spiffe://acme/agent/build-agent`);
tenancy keys off that org.

### 4. The governed control plane

Run `al-gov serve` on the control host, bound to the control network only —
it injects the org/user directory as the core's authenticator and serves the
dashboard plus `/api/orgs|users|attestation|cost`:

```bash
uv run al-gov serve --host <control-net-ip> --port 8888 --config configs/balanced.yaml
```

Front it with your standard reverse proxy for TLS, and keep it unreachable
from any agent network (in the compose topology that is already true by
construction; preserve the property in yours). Give tenants their `alg_`
tokens; every evidence read is org-scoped in the core, so a
governance-layer bug can only narrow what a caller sees, never widen it.

### 5. Per-tenant attestation and cost, on a cadence

Monthly (or per your compliance calendar), for each org:

```bash
uv run al-gov attest export acme -o attestations/acme-$(date +%Y-%m).json
uv run al-verify attestations/acme-*.json --pubkey keys/mediator_ed25519.pub
uv run al-gov cost --org acme --usd-per-mtok <blended rate>
```

The attestation's evidence level (AEL-0..3) is computed, never asserted —
audit mode cannot claim enforcement — and the tenant can verify the file
with `al-verify` alone, no AgentLighthouse runtime and no trust in you.

### 6. SIEM and incident readiness

- Ship `al export --verdict block` output to your SIEM on a schedule; alerts
  carry MITRE technique ids, OWASP ASI tags, `record_hash` + `sig`.
- The kill switch has four sources (control API, `al killswitch` CLI,
  sentinel file touch, SIGUSR1). Put the sentinel path in your incident
  runbook and drill it — engagement is receipted CRITICAL, and `/healthz`
  stays answerable during the incident.
- On sealed agent hosts, apply the L0 ruleset: `al egress nftables --apply`
  (and run `al egress selftest` as the agent-entrypoint precondition, as the
  compose probes do).
- Run agent containers under gVisor: add `-f docker-compose.gvisor.yml` to
  the compose invocation (runsc must be installed on the host). Agents get
  the syscall sandbox; the mediator keeps the native runtime.

## Windows in the enterprise tier

Windows machines are **operator and developer workstations only** in this
tier — the enforcement hosts and Postgres run on Linux. From Windows:

1. Install git, Python 3.12+, uv (as in the dev-community guide) and clone
   the repo to get the CLIs.
2. Administer remotely: SSH port-forward the control plane
   (`ssh -L 8898:127.0.0.1:8898 ops@mediation-host`) and use the dashboard
   at `http://127.0.0.1:8898` with your `alg_` token.
3. Verify evidence and attestations locally — `al-verify` is
   platform-independent: `uv run al-verify <ledger-or-attestation>
   --pubkey <mediator pubkey>`.
4. Full dev parity for changes: the suite and all three demos run on
   Windows before anything ships to the Linux hosts (`uv run pytest -q`,
   `make release`).
