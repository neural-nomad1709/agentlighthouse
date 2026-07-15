# Demo 1 — Tool-Response Injection (RELEASE GATE)

An MCP tool with a harmless name and a harmless description (`web_search`)
hides a prompt-injection payload in its **response**. Descriptor pinning and
poisoning checks pass — there is nothing wrong with the descriptor. The
mediator blocks the payload anyway, on the response, before the agent sees it,
on all three MCP transports.

```bash
make demo
# or
uv run python examples/tool-response-injection/demo.py
```

Checks (each asserted; any failure exits non-zero — **CI treats that as: no release**):

1. Blocked on **stdio** (real subprocess), **HTTP-upstream**, and **HTTP-reverse**.
2. Fixed, agent-legible `block_reason` (`INJECTION_BLOCKED`) on every transport.
3. The exfil payload never reaches the agent and never enters the ledger.
4. Kill switch drills the whole plane to deny-all, then releases.
5. `al-verify` verifies the receipt chain in a subprocess where importing
   `al_core` is forced to fail — the evidence-portability claim, proven.

`mock_server.py` is the hostile MCP server (dependency-free, newline-delimited
JSON-RPC); it serves both the stdio and HTTP transports. The demo builds a
throwaway workspace in `run/` (gitignored). Coverage: ASI01 (goal hijack via
tool response), ASI02 (tool misuse), G1 (explainable intercept).
