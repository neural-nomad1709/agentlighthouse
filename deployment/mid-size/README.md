# Deployment: mid-size (up to 10 users)

**Profile:** a team of up to 10 users behind one always-on mediation host.
**Single-tenant by default** (one organization; an optional multi-org step
is included if sub-teams need separated evidence views). **On-premise or a
self-managed cloud VM** — you own the host either way; there is no hosted
service. The Docker Compose topology provides the enforcement boundary:
agents live on an internal network whose only road out is the mediator, and
the control plane (kill switch, dashboard, admin API) is unreachable from
agents by construction.

**Recommended platform: Linux** (Docker Engine). Windows + Docker Desktop
runs the identical stack for evaluation, with one production gap called out
below.

## Architecture you are deploying

- `al-core` — data plane: `/fetch`, OpenAI/Anthropic reverse proxy, `POST
  /mcp`, CONNECT proxy. Host port `127.0.0.1:8443`.
- `al-control` — control plane: admin API, kill switch, dashboard. Host port
  `127.0.0.1:8898`. Own ledger (one writer per chain). It also mounts the data
  plane's evidence volume at `/app/dataplane` and opens it **read-only**
  (`AL_CONTROL__DATAPLANE_DIR`), so the dashboard shows gateway traffic —
  without it you would see only the control plane's own receipts. Read-only is
  enforced at the SQLite layer, so `al-core` stays the single writer of its
  chain.
- `agent-selftest` + `agent-control-probe` — one-shot probes that must exit
  0 on every `up`, proving the agent network is sealed and has no route to
  the control plane.
- Named volumes `al-data`, `al-control-data` (evidence), `al-killswitch`
  (the sentinel file — the only thing the planes share).

## Linux (production posture)

1. Prerequisites: a Linux host (physical, or a cloud VM you manage) with
   Docker Engine + the compose plugin, git, and — for key generation and the
   CLI — Python 3.12+ with uv. Node.js is **not** required: the dashboard is
   built inside the image (`docker compose build`), so a clone of the repo is
   all you need.

2. Clone and generate the secrets the stack mounts:

   ```bash
   git clone <repo-url> AgentLighthouse && cd AgentLighthouse
   uv sync
   uv run al init --config configs/balanced.yaml     # signing key (0600) + workspace
   [ -f keys/admin_api_token ] || python3 -c "import secrets;print(secrets.token_urlsafe(32),end='')" > keys/admin_api_token
   chmod 600 keys/admin_api_token
   ```

3. Configure policy before first boot:
   - `configs/balanced.yaml` -> `gateway.allow_hosts`: the hosts agents may
     reach (empty = default-deny).
   - `policies/default-deny.yaml`: per-identity tool allow rules.
   - Provider keys go in the environment of `al-core` only (compose
     `environment:` from an env file you do not commit):
     `AL_GATEWAY__UPSTREAM__ANTHROPIC_API_KEY`, `..._OPENAI_API_KEY`.

4. Production key delivery — mount the signing key as a real secret instead
   of the dev auto-generated one. Create `docker-compose.prod.yml`:

   ```yaml
   services:
     al-core:
       environment:
         AL_KEYS__SIGNING_KEY_PATH: /run/secrets/mediator_signing_key
       secrets:
         - source: mediator_signing_key
           target: mediator_signing_key
           uid: "10001"
           mode: 0400
     al-control:
       environment:
         AL_KEYS__SIGNING_KEY_PATH: /run/secrets/mediator_signing_key
       secrets:
         - source: mediator_signing_key
           target: mediator_signing_key
           uid: "10001"
           mode: 0400
   ```

   Leave `AL_ENV`/`AL_MODE` as shipped (`dev`/`balanced`): balanced mode is
   what enforces the gates; the boot-time egress self-test that `env: prod`
   additionally arms belongs on sealed agent hosts, not on the mediator
   (which legitimately has egress). The full prod-env packaging pass is
   Phase 8 scope.

5. Bring it up and demand the proofs:

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
   docker compose logs agent-selftest agent-control-probe   # BOTH must exit 0
   curl http://127.0.0.1:8443/healthz                       # healthy + chain verified
   ```

   If either probe fails, the topology is broken — do not run agents on it.

6. Onboard your users (up to 10). Per user, issue a budgeted virtual key;
   per agent workload, an identity. Run the CLI against the data volume via
   the container:

   ```bash
   docker compose exec al-core al vkey issue alice --max-requests 500 --max-tokens 500000
   docker compose exec al-core al identity issue acme alice-agent
   ```

   Each key/token is shown once — deliver it to the user out of band.

7. Wire agent workloads exactly like `agent-sandbox`: attach to `agent-net`
   only, set `HTTP_PROXY`/`HTTPS_PROXY=http://al-core:8080`, and give the
   agent its identity credentials. LLM SDKs point at
   `http://al-core:8443/v1` with the user's `alk_` key.

8. Operator access (dashboard + kill switch) is loopback on the Docker host:
   `http://127.0.0.1:8898` with `Authorization: Bearer $(cat keys/admin_api_token)`.
   The fleet dashboard ships prebuilt in the image and is served by `al-control`
   at `http://127.0.0.1:8898/dashboard/` — nothing to build, no Node on the host.
   Reach it over SSH port-forwarding rather than exposing the port.

   It shows **both** planes: receipts are tagged `data` / `control`, the
   toolbar gains a plane filter, and the header carries one chain chip per
   plane. Both should read `chain ok`. A chain the dashboard cannot check reads
   `unverified` (amber); `BROKEN` (red) means signatures were checked and
   failed — treat that as tampering and escalate.

9. Drill the kill switch once before going live (see the Phase 5 manual
   tests, Part B) so the team has done it before an incident.

10. Optional — run agent containers under gVisor (user-space kernel syscall
    sandbox). Install runsc on the host (`sudo runsc install`, reload
    Docker), then add the profile:

    ```bash
    docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.gvisor.yml up -d
    ```

    Only the agent workload switches runtime; the mediator stays native. The
    probes still gate every `up`.

### Ongoing operations (Linux)

- **Backups:** `keys/` plus the two evidence volumes
  (`docker run --rm -v agentlighthouse_al-data:/d -v $PWD:/b alpine tar czf /b/al-data.tgz /d`
  and the same for `al-control-data`).
- **SIEM feed:** `docker compose exec al-core al export --verdict block`
  on a schedule, shipped to your SIEM; every event carries `record_hash` +
  `sig` and is independently verifiable.
- **Attestation of the evidence at any time:**
  `docker compose exec al-core al-verify /app/data/ledger.jsonl --pubkey /app/data/keys/mediator_ed25519.pub`.
- **Upgrades:** `git pull`, rebuild (`docker compose build`), verify the
  suite on a workstation (`uv run pytest -q` + `make release`), then
  `docker compose up -d`. The probes re-prove the topology on every up.

### Optional: separated views for sub-teams (single host, multi-org)

If two teams share the host and must not see each other's evidence, enable
the governance layer: create orgs and users with `al-gov` and issue
org-scoped keys (`al vkey issue alice --org team-a`). This is the enterprise
guide's mechanism at smaller scale — see
[../enterprise/README.md](../enterprise/README.md); the governed control
plane (`al-gov serve`) currently runs natively on the host rather than in
the container image.

## Windows (evaluation of this tier)

Docker Desktop runs the identical compose stack — same probes, same gates,
same drills — with one production gap: a Windows host cannot deliver
`/run/secrets` with sane file modes (bind mounts report 0777 and the
fail-closed key policy refuses, correctly), so the stack falls back to the
dev-grade auto-generated signing key on the Linux-native volume, and step 4
above does not apply.

1. Install Docker Desktop, git, Python 3.12+, uv.
2. Follow Linux steps 2-3 in PowerShell (`python -c ...` for the token;
   skip `chmod`).
3. `docker compose up -d --build`, then verify probes and healthz as in
   step 5, and onboard users as in step 6 (`docker compose exec` works the
   same).

Use Windows for the pilot; move the compose files, `configs/`, `policies/`,
and `keys/` to a Linux host for production — the stack is unchanged.
