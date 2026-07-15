# Phase 8 manual tests — Hardening, compliance, packaging

What you verify: the hardening invariants hold as tests, the gVisor overlay
is valid, the one-command pilot install works end to end and refuses an
unproven topology, the packaging pipeline behaves (including failing
clearly when its tools are absent), and the rollout configs validate.

## Environment setup

1. Complete the [common setup](README.md#common-environment-setup).
2. Tests 8.3-8.4 need Docker running. Test 8.5 needs syft (optional);
   8.6 documents the expected failure when syft/cosign are absent.

## Test data preparation

None — Phase 8 is configuration, packaging, and documentation; its inputs
are the repository files themselves.

## Tests

### 8.1 Hardening invariants hold

```
uv run pytest tests/test_hardening.py tests/test_topology.py -q
```

Expected: 18 passed — the compose baseline (caps, privileges, read-only
rootfs, tmpfs, pids/mem limits), non-root image with no secrets in layers,
the governance layer neither copied nor installed, gVisor profile shape, and the
packaging entry points.

### 8.2 gVisor overlay is valid and minimal

```
docker compose -f docker-compose.yml -f docker-compose.gvisor.yml config --quiet
```

Expected: exits 0 (no output) — the overlay merges cleanly. Open
`docker-compose.gvisor.yml`: it contains ONLY `runtime: runsc` for the three
agent-side services, nothing else. Live gVisor execution needs a Linux host
with runsc installed (see the mid-size deployment guide, step 10).

### 8.3 One-command pilot install

Windows:

```
powershell -ExecutionPolicy Bypass -File scripts/pilot-install.ps1
```

Linux/macOS: `make pilot` (or `scripts/pilot-install.sh`).

Expected: six numbered steps — workspace, keys, full test suite, the
release-gate demo, `docker compose up -d --build`, then verification that
BOTH one-shot probes exited 0 and `/healthz` returns 200 — ending with
`pilot install complete.` and the two endpoints. Takes several minutes on a
first run (image build).

### 8.4 The installer is probe-gated (inspection)

Open either installer script: step [6/6] reads each probe's container
`ExitCode` and exits non-zero with "the topology did not prove itself" if
either probe failed. A pilot can never end "complete" on an unsealed
network.

Cleanup for 8.3: `docker compose down -v`.

### 8.5 SBOM generation (requires syft)

```
make sbom
```

Expected with syft installed: `dist/al-core.spdx.json` written; it is SPDX
JSON (`"spdxVersion"` near the top) listing the image's packages. Skip if
syft is not installed — see 8.6.

### 8.6 Packaging fails closed and clearly without its tools

On a machine WITHOUT syft/cosign (a typical dev box):

```
bash scripts/release-image.sh
```

Expected: immediate exit 1 with a one-line error naming the missing tool
and its install URL (e.g. `error: 'syft' is required — ...`). No partial
build, no half-signed artifacts.

### 8.7 Rollout configs all validate

```
uv run al check --config configs/audit.yaml
uv run al check --config configs/balanced.yaml
uv run al check --config configs/strict.yaml
```

Expected: all three exit 0. Cross-check `docs/rollout.md`: strict's config
shows the tighter posture it documents (`allow_ports: [443]`, 1 redirect,
1 MiB fetch cap, halved budgets).

### 8.8 Compliance docs are present and honest

Open `docs/compliance/README.md` and follow its table: NIST 800-53, EU AI
Act, SOC 2, and MCP-threats mappings each tie every claim to a mechanism
plus its receipt evidence, and each carries the "planning aid, not a legal
opinion" disclaimer. The MCP doc's "Honest gaps" section must match the
README's "What this does NOT do" section.

## Cleanup

```
docker compose down -v        # if 8.3 left the stack up
```

`dist/` (the SBOM output) is gitignored; remove it if you want a clean tree.
