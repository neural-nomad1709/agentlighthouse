# Compliance mappings

Engineering planning aids that map AgentLighthouse mechanisms to the control
frameworks a pilot's security review will ask about. **They are not legal
opinions, not certifications, and not a substitute for your own assessment.**
Every claim maps to a shipped, tested mechanism; where coverage is partial or
absent, the mapping says so (the README's "What this does NOT do" section is the
master honesty statement).

| Framework | Document |
|-----------|----------|
| OWASP Agentic Top 10 (2026) | [`../owasp-mapping.md`](../owasp-mapping.md) (canonical, verified taxonomy) |
| MCP-specific threats | [mcp-threats.md](mcp-threats.md) |
| NIST SP 800-53 rev. 5 | [nist-800-53.md](nist-800-53.md) |
| EU AI Act | [eu-ai-act.md](eu-ai-act.md) |
| SOC 2 (Trust Services Criteria) | [soc2.md](soc2.md) |

## Why these mappings are checkable, not aspirational

Most compliance mapping documents assert coverage. These can be audited,
because the product's core output is **evidence**:

- Every mediated decision produces a mediator-signed, hash-chained receipt
  (spec: `spec/receipt-v1.md`). An auditor verifies any receipt or the whole
  ledger with the standalone `al-verify` — no AgentLighthouse runtime, no
  trust in the operator's binary.
- Per-organization **posture attestations** are signed and carry a computed
  evidence level (AEL-0..3). Enforcement cannot be claimed from audit mode —
  the level is derived from the evidence, never asserted.
- SIEM exports carry `record_hash` + `sig`, so an alert in your SOC tooling
  traces back to a verifiable receipt.

When a row in these mappings cites a mechanism, the receipts that mechanism
emits are the audit evidence; the tests in `tests/` are
the design-effectiveness evidence.
