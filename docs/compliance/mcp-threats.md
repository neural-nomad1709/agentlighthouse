# MCP threat coverage (planning aid)

The Model Context Protocol is the main tool-connectivity surface for agents,
and most published MCP attacks target the gap between "the tool looked safe
when approved" and "what it actually did at call time". AgentLighthouse
mediates all three MCP transports (stdio subprocess, HTTP upstream,
`POST /mcp` reverse ingress) through one filter, so coverage below applies
regardless of how the server is attached.

| Threat | Attack shape | Mechanism | Proven by |
|--------|-------------|-----------|-----------|
| Tool poisoning | Hostile instructions embedded in a tool's name/description, executed when the agent reads the catalog | Every `tools/list` descriptor runs through the L2/L3 content gate (evasion-folded variants included); hostile descriptors are removed before the agent ever sees them | `test_mcp.py`; manual test 3.7 (`TOOL_POISONED`) |
| Rug-pull (descriptor drift) | Tool approved clean, description silently changed later | Descriptor pinning: SHA-pinned at approval, ANY drift — hostile or benign — is withheld until an operator re-approves; pins persist across restart | manual test 3.8 (`TOOL_DESCRIPTOR_DRIFT`); Demo 3 shows the same defence on A2A Agent Cards |
| Tool-response injection | Clean name, clean description — the payload arrives in the tool's *response* | Tool responses are scanned before delivery: injection withheld, secrets redacted in place. **This is the release gate** — blocked on all three transports or no release ships | `make demo`; `test_mcp_transport.py` |
| Argument exfiltration | A *permitted* tool call carries secrets/PII/context out in its own arguments | Outbound DLP on tool-call arguments: secret/PII redacted in flight (the call still runs), seed phrases and injection payloads block the call | `test_tool_args.py` |
| Unauthorized tool use | Agent calls tools outside its mandate, or with hostile arguments | Identity-bound default-deny policy with per-argument constraints (hosts, path prefixes with traversal normalization, values, length); explicit deny wins | `test_tool_policy.py`; manual tests 3.1-3.4 |
| Recon -> stage -> exfil chains | Individually-allowed calls composing into an exfiltration sequence, spaced out through benign traffic | Chain detector: gap-tolerant ordered-subsequence matching across the session (`TOOL_CHAIN_DETECTED`) | `test_mcp.py` |
| Irreversible actions on attacker say-so | Injected content steers the agent into send/delete/transfer/pay | HITL gate pauses irreversible verbs for human approval (timeout -> deny); untrusted ingestion taints the session and widens the paused set | `test_taint_hitl.py` |
| Instruction-file poisoning | `SKILL.md` / `CLAUDE.md` / `.cursorrules` carries the injection into the agent's own instructions | SkillGuard screens + pins instruction files: poisoned withheld, drift held for re-approval, secrets redacted; doubles as a CI gate (`al skill check`) | `test_skills.py`; manual tests 3.9-3.10 |
| Kill-switch bypass via MCP | Agent keeps calling tools during an incident | The kill switch is enforced at the ActionGate and every ingress, including `POST /mcp` — engaged means the JSON-RPC error, not the tool | `make demo` step [4] |

## Honest gaps

- MCP HTTP upstreams that answer with **SSE streams** are not yet consumed
  (JSON replies are); the reverse ingress shares the limit. The stdio and
  JSON paths — the common cases — are covered.
- A denied `tools/call` never reaches the server, but AgentLighthouse does
  not authenticate the MCP *server* itself beyond its pinned descriptors —
  server-side compromise that produces clean descriptors and clean responses
  with hostile *side effects* on the server is out of scope for a mediator.
- Sender identity on inter-agent (A2A) messages is asserted, not
  cryptographically proven.
