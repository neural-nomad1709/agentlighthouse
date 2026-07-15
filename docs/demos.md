# DEMOS.md — Three Runnable Partner Demos

> Every security claim has a runnable scenario behind it. Nothing in the deck is vaporware. Each demo is laptop-runnable (no partner infra) and ends by verifying a signed receipt.

## Status: all three SHIPPED and passing (2026-07-12)

| Demo | Command | Delivered | Coverage |
|------|---------|-----------|----------|
| 1. Tool-response injection | `make demo` | Phase 5 — **the release gate** | ASI01, ASI02 |
| 2. Memory poisoning + rollback | `make demo-memory` | Phase 4 | ASI06 |
| 3. A2A interception harness | `make demo-a2a` | Phase 7 | ASI07 |

`make release` = full suite + all three. Each demo runs as an acceptance test in
the suite, so a demo cannot rot silently between partner calls. Each builds a
throwaway workspace (`examples/*/run/`, gitignored) and ends by verifying its
receipts with the standalone `al-verify`.

---

## Demo 1 — Tool-Response Injection (RELEASE GATE) — **SHIPPED (P5)**
**Story:** An MCP tool with a harmless name/description hides a prompt-injection payload in its *response*. AgentLighthouse blocks the response before the agent sees it.
**Run:** `make demo` → `examples/tool-response-injection/`
**Coverage:** ASI01 (goal hijack via tool response), ASI02 (tool misuse), G1 (explainable intercept).
**Pass:**
- Blocked on **stdio + HTTP-upstream + HTTP-reverse** MCP transports (one shared signing key).
- Dashboard shows the intercept with fixed `block_reason` + highlighted payload (explainability).
- `al-verify receipt.json` verifies independently — **no al-core imported.**
- **CI: if this fails, no release.**

## Demo 2 — Memory Poisoning + Rollback — **SHIPPED (P4)**
**Story:** A poisoned entry is written to a local vector store / scratchpad. AgentLighthouse screens the write, blocks + quarantines it, and rolls back to the integrity baseline.
**Run:** `make demo-memory` → `examples/memory-poison/` (uses the memory-guard compose profile; fully local).
**Coverage:** ASI06 (memory & context poisoning).
**Pass:**
- Poison payload blocked on write; protected-key tamper detected.
- `al rollback` restores known-good state; before/after hashes shown.
- Signed receipt for the block verifies.
**Partner value:** demonstrable with zero partner infrastructure — this is a shipped feature *and* a sales demo.

## Demo 3 — A2A Interception Harness — **SHIPPED (P7)**
**Story:** Two mock agents in the test compose profile talk to each other. One attempts **Agent-Card poisoning** and **session smuggling**. AgentLighthouse mediates between them and intercepts both.
**Run:** `make demo-a2a` → `examples/a2a-lab/` (a2a-lab compose profile; two mock agents, no real multi-agent topology needed).
**Coverage:** ASI07 (insecure inter-agent comms).
**Pass (all verified, 2026-07-12):**
- Agent-Card **poisoning** blocked before the payload is even considered (`A2A_CARD_POISONED`).
- Agent-Card **drift** blocked — a card that quietly gains a `wire_transfer` skill is a rug-pull (`A2A_CARD_DRIFT`), held until an operator re-approves.
- **Session smuggling** denied: a session id belongs to the peer pair that opened it, so a third agent replaying it is refused (`A2A_SESSION_SMUGGLED`).
- All three interceptions receipted (`a2a_message`, ASI07-tagged); the exfil host never enters the ledger; `al-verify` verifies the chain from genesis.
**Graduation:** the mediator, pinning, smuggling checks and receipts are production code in `core/al_core/a2a/` — what a real multi-agent partner still needs is an A2A *transport* (HTTP/gRPC), the same shape as the MCP transport shell Phase 5 added. They get a transport, not new policy.

---

## Demo hygiene (all three)
- Self-contained; `make <demo>` spins up only the needed profile.
- Each ends with an independent `al-verify` step — proving evidence portability, the core differentiator.
- Each maps explicitly to an ASI risk on screen, so a security reviewer sees coverage, not just a green check.
- Recorded (asciinema/GIF) for the partner deck; the live run is the credibility.
