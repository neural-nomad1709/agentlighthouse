# Examples

Three demos, each an end-to-end attack against AgentLighthouse that the
mediator is supposed to stop. They are not illustrative snippets: every one is
a self-verifying program that asserts its own claims and exits non-zero if any
of them fails to hold.

| Demo | Run | Proves | OWASP |
|------|-----|--------|-------|
| [tool-response-injection](tool-response-injection/) | `make demo` | A hostile MCP server with a *clean* name and description hides an injection payload in its tool **response**; blocked on all three MCP transports | ASI01, ASI02 |
| [memory-poison](memory-poison/) | `make demo-memory` | A poisoned memory write is blocked and quarantined; an out-of-band tamper of a protected key is caught; rollback restores known-good | ASI06 |
| [a2a-lab](a2a-lab/) | `make demo-a2a` | Agent-Card poisoning, card drift (rug-pull) and session smuggling are all intercepted between two agents | ASI07 |

Prose walkthroughs of the attacks live in [`docs/demos.md`](../docs/demos.md).
This file is about how they are wired into the build.

## Why these matter: `make demo` is the release gate

`make demo` (demo 1) is the release gate. **If it fails, there is no release** —
that rule is enforced in CI, not just written down. It is the demo worth reading
first, because it is the one that defends the claim the product is built on: the
tool descriptor is clean, descriptor pinning and poison-scanning both pass, and
the mediator blocks the payload anyway, on the response, before the agent sees
it. It also proves evidence portability the hard way, verifying the receipt
chain in a subprocess where importing `al_core` is forced to raise `ImportError`.

Demos 2 and 3 are not release gates, but they are the acceptance criteria for
Phase 4 (memory guard) and Phase 7 (A2A harness) respectively, and they run in
CI alongside demo 1.

## Where they are used in code

Each demo is exercised from three directions, so it cannot rot silently.

**1. The test suite runs them.** Each demo is spawned as a subprocess by a real
pytest test that asserts a zero exit code:

| Demo | Test |
|------|------|
| tool-response-injection | `tests/test_mcp_transport.py::test_demo_release_gate_passes` |
| memory-poison | `tests/test_memory_guard.py::test_demo_memory_poison_runs_end_to_end` |
| a2a-lab | `tests/test_a2a.py::test_demo_a2a_runs_end_to_end` |

This means the demos are covered by a plain `uv run pytest -q`, and the paths
below are load-bearing — renaming or moving a demo directory breaks the suite.

**2. CI runs them** as explicit steps after the suite, in
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml): `make demo` (labelled
the release gate), then `make demo-memory`, then `make demo-a2a`.

**3. The Makefile exposes them**, individually and together:

```bash
make demo          # RELEASE GATE: tool-response injection, all 3 MCP transports
make demo-memory   # memory poisoning blocked, tamper detected, rollback restores
make demo-a2a      # agent-card poisoning, rug-pull, session smuggling intercepted
make release       # the full suite plus all three demos
```

They are also cited from the manual test guides — see below — and from
`docs/owasp-mapping.md`, `docs/compliance/mcp-threats.md` and
`docs/architecture.md`, where each control's claim points at the demo that
substantiates it.

## Relationship to `manual-tests/`

[`manual-tests/`](../manual-tests/README.md) is the human-operator counterpart:
markdown checklists, one per build phase, for someone verifying the controls by
hand on a new machine. It does not reimplement these attacks — it *invokes*
them. Phase 4 runs `make demo-memory`, Phase 5 runs `make demo`, and Phase 7
runs `make demo-a2a` as steps inside their own guides, and Phase 3 defers its
tool-policy cases to the Phase 5 demo.

So the split is: `examples/` owns the executable attacks (automated, CI-gated),
`manual-tests/` owns the human procedure and borrows them. One implementation,
two audiences.

## How a demo works

Every demo is fully local and self-contained. There is no network dependency, no
fixture to install, and nothing to clean up:

- It builds a throwaway workspace under its own `run/` directory — a fresh dev
  signing key, config, ledger and data store — and deletes it on each re-run.
  All three `run/` directories are gitignored.
- It narrates itself in numbered steps, printing `PASS` or `FAIL` per claim.
- It ends by verifying its own signed receipt chain with the standalone
  `al-verify`, which does not depend on the runtime that produced the receipts.
- **Exit code 0 means every claim held.** Any failed check exits non-zero.

Run one directly, without `make`:

```bash
uv run python examples/tool-response-injection/demo.py
```

## Layout

```
examples/
├── tool-response-injection/   # Demo 1 — RELEASE GATE
│   ├── demo.py
│   ├── mock_server.py         # the hostile MCP server; serves stdio AND HTTP
│   └── run/                   # throwaway workspace (gitignored)
├── memory-poison/             # Demo 2
│   ├── demo.py
│   └── run/
└── a2a-lab/                   # Demo 3
    ├── demo.py
    └── run/
```
