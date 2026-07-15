# Deployment: dev / community (up to 2 users)

**Profile:** one developer or a two-person team running AgentLighthouse on a
workstation. **Single-tenant. On-premise** (your own machine — no cloud
services required, no vendor hosting). Evidence in SQLite + the canonical
JSONL ledger. Suitable for development, evaluation, and laptop demos — not
for production enforcement.

Two ways to run it: **native** (option A — Windows, Linux, or macOS; no
Docker) and the **Docker topology** (option B — adds the sealed agent
network). Most dev-community users want option A and add B for demos.

## Option A — native

### Windows

1. Install prerequisites:
   - Python 3.12+ (`winget install Python.Python.3.12`)
   - uv (`winget install astral-sh.uv`)
   - Git; Node.js 20+ only if you want the dashboard UI *from source*. It is
     not needed for the Docker path — that image ships the dashboard prebuilt
     (see `deployment/mid-size/`).
2. Clone and install:

   ```powershell
   git clone <repo-url> AgentLighthouse
   cd AgentLighthouse
   uv sync
   ```

3. Initialize the workspace (creates `keys/` with the Ed25519 signing key,
   `data/`, and `.env` holding a dev admin token):

   ```powershell
   uv run al init --config configs/balanced.yaml
   ```

4. Prove the install (the release gate is the acceptance bar):

   ```powershell
   uv run pytest -q          # expect: 630 passed, 12 skipped
   make release              # full suite + all three demos, if make is available
   ```

   Without make, run the three demos directly:
   `uv run python examples/tool-response-injection/demo.py`, then
   `examples/memory-poison/demo.py`, then `examples/a2a-lab/demo.py`.

5. Allowlist the hosts your agents may reach: edit
   `configs/balanced.yaml` -> `gateway.allow_hosts` (empty list =
   default-deny everything).

6. Create your (up to 2) users and agent identities — each token/key is
   shown once:

   ```powershell
   uv run al identity issue home alice-agent
   uv run al vkey issue alice --max-requests 200 --max-tokens 200000
   ```

7. Provide LLM provider keys via environment (never YAML):
   `$env:AL_GATEWAY__UPSTREAM__ANTHROPIC_API_KEY = "..."` and/or
   `AL_GATEWAY__UPSTREAM__OPENAI_API_KEY`.

8. Start the data plane and point agents at it:

   ```powershell
   uv run al gateway --host 127.0.0.1 --config configs/balanced.yaml
   ```

   - LLM traffic: base URL `http://127.0.0.1:8443/v1` with the `alk_`
     virtual key as the API key.
   - Web/tool egress: `GET /fetch?url=` with the identity headers, or
     `HTTP(S)_PROXY=http://127.0.0.1:8080` with proxy credentials
     `spiffe-id:token`.
   - MCP servers: `uv run al mcp proxy --actor <spiffe-id> -- <server cmd>`.

9. Dashboard (optional). The gateway from step 8 is still running and is the
   single writer of `data/`, so give the dashboard its **own** data dir and
   attach the gateway's **read-only** — never point `--data-dir` at a running
   gateway's dir, or two writers race one hash chain:

   ```powershell
   npm --prefix frontend install
   npm --prefix frontend run build
   uv run al dashboard --data-dir data/control `
                       --dataplane-dir data `
                       --dataplane-pubkey keys/mediator_ed25519.pub
   # http://127.0.0.1:8899/dashboard/, token from .env
   ```

   `--dataplane-pubkey` is what lets the dashboard *verify* the gateway's
   chain. It defaults to `<dataplane-dir>/keys/mediator_ed25519.pub`, which is
   where the container image keeps the key — a native install keeps it in
   `keys/`. Omit it here and the receipts still appear, but that chain is
   reported `unverified` (we could not check it) rather than verified.

### Linux (and macOS)

Identical flow; the syntax differences:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh     # uv
git clone <repo-url> AgentLighthouse && cd AgentLighthouse
uv sync
uv run al init --config configs/balanced.yaml
uv run pytest -q && make release
uv run al identity issue home alice-agent
uv run al vkey issue alice --max-requests 200 --max-tokens 200000
export AL_GATEWAY__UPSTREAM__ANTHROPIC_API_KEY="..."
uv run al gateway --host 127.0.0.1 --config configs/balanced.yaml

# dashboard, in a second shell (same two-dir rule as step 9):
npm --prefix frontend install && npm --prefix frontend run build
uv run al dashboard --data-dir data/control \
                    --dataplane-dir data \
                    --dataplane-pubkey keys/mediator_ed25519.pub
```

On Linux you can additionally render (and, on an agent host, apply) the L0
nftables default-deny ruleset: `uv run al egress nftables [--apply]`.

## Option B — Docker topology

Requires Docker Desktop (Windows) or Docker Engine + compose (Linux).

One-command path: `make pilot` (Linux/macOS) or
`powershell -ExecutionPolicy Bypass -File scripts/pilot-install.ps1`
(Windows) runs steps 1-4 of Option A plus this whole section, and fails
unless both topology probes prove the boundary. The manual steps:

1. Ensure `keys/admin_api_token` exists (compose mounts it as a secret);
   `al init` + the Phase-5 manual test prep create it if needed.
2. Bring the stack up — two one-shot probes must exit 0 before the agent
   sandbox starts:

   ```
   docker compose up -d --build
   docker compose logs agent-selftest agent-control-probe
   ```

3. Verify: `curl http://127.0.0.1:8443/healthz` (data plane, healthy +
   chain verified); control plane on `127.0.0.1:8898` (admin token gated).
4. Windows note: the host cannot deliver `/run/secrets` with sane modes, so
   the dev stack auto-generates the signing key on the Linux-native volume —
   fine for this tier; the mid-size guide shows the production key path.
5. Tear down with `docker compose down -v`.

## Operations

- **Backups:** copy `keys/` (the signing key is the root of evidence trust)
  and `data/` (ledger + mirror + stores). Both are plain files.
- **Upgrades:** `git pull && uv sync && uv run pytest -q` — do not adopt a
  build whose suite is red. `make release` is the acceptance bar.
- **Verification at any time:**
  `uv run al-verify data/ledger.jsonl --pubkey keys/mediator_ed25519.pub`.
- **Scaling out:** at the point you have more than 2 users or need an
  always-on host, move to [mid-size](../mid-size/README.md) — same
  configs and keys carry over.
