# Demo 2 — Memory Poisoning + Rollback (ASI06)

A poisoned entry is written to the agent's memory store. AgentLighthouse
screens the write, blocks and quarantines it; an out-of-band tamper of a
protected key is caught against the SHA-256 integrity baseline; rollback
restores the known-good snapshot; the signed receipts verify with the
standalone `al-verify` (no al-core runtime required).

```bash
make demo-memory
# or
uv run python examples/memory-poison/demo.py
```

Fully local: the demo builds a throwaway workspace in `examples/memory-poison/run/`
(gitignored) with its own dev signing key, ledger, and memory store. Exit code
0 means every claim held. Coverage: OWASP ASI06 (memory & context poisoning).
