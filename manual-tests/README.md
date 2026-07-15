# Manual test guides

Step-by-step manual verification of every build phase, one document per phase.
These complement the automated suite (`uv run pytest -q`, 615 tests) — they are
for a human operator who wants to see each control work with their own eyes,
and for acceptance sign-off on a new machine.

| Document | Phase | What you verify |
|----------|-------|-----------------|
| [phase-0-foundations.md](phase-0-foundations.md) | 0 | Workspace init, config validation, receipts, hash chain, tamper evidence, SQLite mirror |
| [phase-1-edge-gate.md](phase-1-edge-gate.md) | 1 | SSRF blocking, DNS pinning, identity-gated proxies, virtual keys + budgets, egress self-test, Docker topology |
| [phase-2-content-gate.md](phase-2-content-gate.md) | 2 | Injection/secret/seed-phrase/PII scanning, evasion folding, gateway DLP, dashboard |
| [phase-3-action-gate.md](phase-3-action-gate.md) | 3 | Identity-bound tool policy, argument constraints, MCP descriptor pinning + poison scan |
| [phase-4-memory-guard.md](phase-4-memory-guard.md) | 4 | Guarded memory reads/writes, quarantine, protected-key tamper detection, snapshot + rollback |
| [phase-5-evidence-control.md](phase-5-evidence-control.md) | 5 | MCP transports (release gate), kill switch, SIEM export, control/data plane segregation |
| [phase-6-governance.md](phase-6-governance.md) | 6 | Orgs, RBAC, tenant isolation, signed attestation, cost reporting, Postgres concurrency |
| [phase-7-learning-a2a.md](phase-7-learning-a2a.md) | 7 | A2A card poisoning/drift/smuggling interception, learning-loop round-trip |
| [phase-8-hardening-packaging.md](phase-8-hardening-packaging.md) | 8 | Hardening invariants, gVisor overlay, pilot install, SBOM/signing pipeline, rollout configs |

## The demos these guides invoke

Three attacks are not re-created by hand here — they are executable, and these
guides call them. They live in [`examples/`](../examples/README.md), run in CI,
and are each covered by the automated suite:

| Invoked by | Command | Attack |
|------------|---------|--------|
| Phase 5 (and Phase 3, which defers its tool-policy cases to it) | `make demo` | Tool-response injection, blocked on all three MCP transports. **This is the release gate** — if it fails, there is no release |
| Phase 4 | `make demo-memory` | Memory poisoning blocked, protected-key tamper detected, rollback restores |
| Phase 7 | `make demo-a2a` | Agent-Card poisoning, card drift, and session smuggling intercepted |

Each demo builds its own throwaway workspace, prints `PASS`/`FAIL` per claim,
and exits non-zero if any claim fails — so when a phase document tells you to
run one, a zero exit code *is* the result you are checking for. The attacks
themselves are written up in [`docs/demos.md`](../docs/demos.md).

## Common environment setup

Every phase document assumes this baseline. Do it once per machine; each
document then adds its own phase-specific setup on top.

### Prerequisites

- Python 3.12+ and [uv](https://docs.astral.sh/uv/)
- Git
- For the dashboard tests (Phases 2, 6): Node.js 20+
- For the topology tests (Phases 1, 5) and Postgres tests (Phase 6): Docker
  (Docker Desktop on Windows, Docker Engine on Linux)

### Steps

1. Open a terminal in the repository root
   (`C:\AILab\projects\AgentLighthouse` on Windows, or wherever you cloned it).
2. Install the workspace:

   ```
   uv sync
   ```

3. Initialize the dev workspace (idempotent — safe to re-run):

   ```
   uv run al init --config configs/balanced.yaml
   ```

   This creates `keys/` (Ed25519 mediator signing key, mode 0600), `data/`,
   and `.env` containing a dev `AL_ADMIN_API_TOKEN`. Expect
   `config OK — mode=balanced env=dev`.

4. Confirm the automated suite is green before any manual session — a red
   suite invalidates manual results:

   ```
   uv run pytest -q
   ```

   Expect `630 passed, 12 skipped` (skips are POSIX/Linux/Postgres-gated).

### Resetting to a clean slate

Manual tests write receipts to `data/ledger.jsonl` and state under `data/`.
To start a phase from a clean ledger, stop any running `al` process, then:

- Windows (PowerShell): `Remove-Item -Recurse -Force data; uv run al init --config configs/balanced.yaml`
- Linux/macOS (bash): `rm -rf data && uv run al init --config configs/balanced.yaml`

Keys in `keys/` are kept (deleting them invalidates trust in prior ledgers).

## Conventions used in every document

- **Shell**: commands are written for PowerShell on Windows. They are
  identical on Linux/macOS unless a "Linux:" variant is shown. On Windows,
  use `curl.exe` (the real curl), not the PowerShell `curl` alias.
- **Exit codes are part of the contract** and are asserted throughout:
  0 = allow/clean, 2 = redacted/stripped, 3 = blocked/denied/tampered/engaged.
  Check the last command's exit code with `$LASTEXITCODE` (PowerShell) or
  `echo $?` (bash).
- **Checking results**: every mediated decision leaves a signed receipt.
  After any test you can inspect the evidence three ways:
  - `uv run al db stats` — aggregate counts (events, verdicts, actions);
  - `uv run al export --verdict block` — blocked decisions as SIEM events;
  - `uv run al-verify data/ledger.jsonl --pubkey keys/mediator_ed25519.pub`
    — independent verification of the whole chain. Expect
    `chain of N receipt(s) verified from genesis  OK` at every checkpoint.
- **Block reasons** ride the `X-AL-Block-Reason` HTTP header and the receipt's
  `block_reason` field; expected values are stated per test.
