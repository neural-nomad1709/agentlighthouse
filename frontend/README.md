# AgentLighthouse — Fleet Dashboard (`frontend/`)

The governance observability dashboard: a progressive-disclosure view of the
evidence ledger. This is the **Phase 6 fleet dashboard** built early — RBAC-aware
and org-tenancy-scoped from day one, so the multi-org governance phase adds
backend enforcement without a UI rewrite.

- **License:** MIT. One canonical dashboard, no duplication.
- **Stack:** Vite + React + TypeScript, built to static assets. Node is a
  build toolchain only — the built `dist/` is served by the Python control
  plane on control-net, and is prebuilt into the container image. No emojis.

## Layout

Two boards behind header tabs — an operator watching an incident and an operator
reviewing the week want different pages.

**Top (both)** — global controls: regex search over actor/target/reason;
time-range segments (1h/24h/7d/30d); verdict/action/org/plane filters;
auto-refresh. Header chips carry mode, kill switch, and one chain chip *per
evidence plane*.

**Trace board** (live incident view)

- **Left** — live receipt stream: dense rows, colour-coded verdict pills, enter
  animation on new items, click to inspect.
- **Center** — **Alert center**: every `block` and `ask` in the window as a
  full-context card (agent, session, plane, seq, rule, signed hash), so the
  who/where of an alert never has to be hunted for.
- **Right** — receipt detail + in-place **Verify** (runs the standalone
  signature/chain check), findings with OWASP/MITRE tags, evidence hashes.

**Performance board** (analytical view)

- Posture tiles (events per plane, blocked, held, redactions, latency p50/p95);
  interactive stacked-bar trends (drag across it to filter to a time window);
  blocked-or-held rate; decision-latency percentiles; top-N breakdowns
  (block reasons, agents, actions); chain + kill-switch posture.

Color discipline: red = block/severity, green = allow/verified, amber =
warn/strip. Red is reserved: a chain we could not *check* reads amber
`unverified`, never red `BROKEN` — that word means tampering. Dark-first, light
theme via the header toggle.

## Evidence planes

Each plane owns its ledger and is its single writer. The dashboard runs on the
control plane, so it attaches the data plane's ledger **read-only** and merges
the two (`core/al_core/audit/pool.py`); receipts arrive plane-tagged and each
chain is verified separately. Without that, gateway traffic — the only traffic
an operator cares about — never appears.

## Develop

```bash
cd frontend
npm install
npm run dev        # http://localhost:5273/dashboard/  (proxies /api to :8899)
```

Run the backend it talks to in another terminal:
`uv run al dashboard --port 8899` (admin-token gated).

## Build + serve (production path)

```bash
npm run build                       # -> frontend/dist (static assets)
# Attach the running gateway's ledger read-only. Its own --data-dir must NEVER
# be the gateway's dir (two writers, one chain). --dataplane-pubkey defaults to
# <dataplane-dir>/keys/... (the container layout); a native install keeps keys/
# beside the repo, so pass it or that chain reads "unverified".
uv run al dashboard --data-dir data/control --dataplane-dir data \
                    --dataplane-pubkey keys/mediator_ed25519.pub
```

Under Docker this is already wired: compose mounts the `al-data` volume into
`al-control` at `/app/dataplane` and sets `AL_CONTROL__DATAPLANE_DIR`, and the
image keeps the key under the data dir, so the default resolves.

## RBAC & tenancy (Phase-6 ready)

`GET /api/session` returns the caller's role (`admin`/`operator`/`viewer`), a
**capability set** (`view`/`verify`/`approve`/`configure`), and the visible
orgs. The UI gates actions on capabilities, never on the role name, and scopes
by org — so per-user RBAC and per-tenant isolation slot in behind the same API.

## End-to-end tests

```bash
npx playwright install chromium
npm run test:e2e     # boots a seeded control plane + drives the built app
```

`e2e/serve.py` seeds a temp ledger across orgs, verdicts, and latencies and
serves the built dashboard; `e2e/dashboard.spec.ts` (9 tests) covers login, the
trace board + per-plane chain status, the alert center (blocks and holds only,
with context), the performance board (trends, rate, latency percentiles,
posture), receipt detail + verify, search, verdict + org filters, and the theme
toggle.
