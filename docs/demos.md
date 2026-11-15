# Demos

> Three runnable attack scenarios. Each one runs on a laptop with no external infrastructure, asserts its own claims, and ends by verifying its signed receipts with the standalone verifier.

| Demo | Command | Coverage |
|------|---------|----------|
| 1. Tool-response injection | `make demo` (**the release gate**) | ASI01, ASI02 |
| 2. Memory poisoning + rollback | `make demo-memory` | ASI06 |
| 3. A2A interception | `make demo-a2a` | ASI07 |

`make release` runs the full test suite plus all three. Each demo also runs as
an acceptance test in the suite. Each builds a throwaway workspace
(`examples/*/run/`, gitignored), prints `PASS` or `FAIL` per claim, and exits
non-zero if any claim fails.

Without `make`, run a demo directly:

```bash
uv run python examples/tool-response-injection/demo.py
uv run python examples/memory-poison/demo.py
uv run python examples/a2a-lab/demo.py
```

---

## Demo 1 — Tool-response injection (release gate)

**Story:** An MCP tool with a harmless name and a harmless description hides a prompt-injection payload in its *response*. Descriptor pinning and poisoning checks pass, because nothing is wrong with the descriptor. The mediator blocks the response before the agent sees it.

**Run:** `make demo` → `examples/tool-response-injection/`

**Coverage:** ASI01 (goal hijack via tool response), ASI02 (tool misuse).

**Checks:**
- Blocked on all three MCP transports: **stdio** (a real subprocess), **HTTP upstream** and **HTTP reverse**, with one signing key.
- A fixed, machine-readable `block_reason` (`INJECTION_BLOCKED`) on every transport.
- The exfiltration payload never reaches the agent and never enters the ledger.
- The kill switch drills the whole mediator to deny-all, then releases.
- `al-verify` verifies the receipt chain in a subprocess where importing `al_core` is forced to fail, so the evidence is shown to be verifiable without the runtime.
- **In CI, a failure of this demo blocks the release.**

## Demo 2 — Memory poisoning + rollback

**Story:** A poisoned entry is written to the agent's memory store. The mediator screens the write, blocks it and quarantines it. A protected key is then tampered with out-of-band, and the tamper is caught against its SHA-256 integrity baseline. Rollback restores the known-good snapshot.

**Run:** `make demo-memory` → `examples/memory-poison/`

**Coverage:** ASI06 (memory and context poisoning).

**Checks:**
- The poison payload is blocked on write (`MEMORY_POISON_BLOCKED`) and quarantined.
- The out-of-band tamper of a protected key is detected on read (`PROTECTED_KEY_TAMPERED`).
- Rollback restores the known-good state; the store hash before and after is shown.
- The receipts carry no payload plaintext, and the chain verifies with `al-verify`.

## Demo 3 — A2A interception

**Story:** Two mock agents talk to each other. Alice is doing legitimate work with Bob; Mallory tries to subvert it. The mediator sits between them and intercepts each attempt.

**Run:** `make demo-a2a` → `examples/a2a-lab/`

**Coverage:** ASI07 (insecure inter-agent communication).

**Checks:**
- A clean message is delivered and the recipient's Agent Card is pinned.
- Agent-Card **poisoning** is blocked before the payload is considered (`A2A_CARD_POISONED`).
- Agent-Card **drift** is blocked: a card that quietly gains a `wire_transfer` skill is a rug-pull (`A2A_CARD_DRIFT`), held until an operator re-approves it.
- **Session smuggling** is denied: a session id belongs to the peer pair that opened it, so a third agent replaying it is refused (`A2A_SESSION_SMUGGLED`).
- A clean peer message still taints the session, so a later protected tool call needs approval.
- Every interception is receipted (`a2a_message`, tagged ASI07), the exfiltration host never enters the ledger, and `al-verify` verifies the chain from genesis.

The demo exercises the mediator, the pinning, the smuggling checks and the receipts with mock agents. It does not include a network transport between agents.

---

## Common properties

- Self-contained: no network dependency, no fixture to install, nothing to clean up.
- Each ends with an independent `al-verify` step.
- Each maps to a named OWASP Agentic risk, so a reviewer sees which risk a passing run covers.
