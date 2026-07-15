# Demo 3 — A2A Interception Harness (ASI07)

Two mock agents talk to each other. Alice is doing legitimate work with Bob;
Mallory tries to subvert it. AgentLighthouse mediates between them, intercepts
every attempt, receipts each interception, and the receipts verify with the
standalone `al-verify`.

```bash
make demo-a2a
# or
uv run python examples/a2a-lab/demo.py
```

Checks (each asserted; any failure exits non-zero):

1. A clean Alice-to-Bob message is delivered and Bob's Agent Card is **pinned**.
2. **Card poisoning** — Bob's card is swapped for one whose description carries
   an injection payload. Blocked (`A2A_CARD_POISONED`) before the payload is
   even considered, and the message is withheld from the recipient.
3. **Card drift / rug-pull** — a benign-looking card quietly adds a
   `wire_transfer` skill. Blocked (`A2A_CARD_DRIFT`) until an operator
   re-approves it.
4. **Session smuggling** — Mallory replays the session id belonging to the
   Alice-Bob conversation to inherit its context and its trust. Denied
   (`A2A_SESSION_SMUGGLED`).
5. A clean peer message still **taints** the session, so a later protected tool
   call needs approval — peer output is untrusted ingestion.
6. Every interception leaves a signed receipt mapped to ASI07, the exfil
   endpoint never enters the ledger, and the chain verifies from genesis.

Fully local: the demo builds a throwaway workspace in `examples/a2a-lab/run/`
(gitignored) with its own dev signing key and ledger. Exit code 0 means every
claim held. Coverage: OWASP ASI07 (insecure inter-agent communication).

What a real multi-agent partner adds here is a *transport* (HTTP/gRPC), not new
policy — the mediation, pinning, smuggling checks and receipts are the same.
