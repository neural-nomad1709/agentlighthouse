# AgentLighthouse Receipt v1 — Evidence Specification

> **License:** MIT. This document and `receipt-v1.schema.json` are the
> portable, vendor-neutral evidence format at the center of AgentLighthouse.
> They are published *first* (D8) so third parties can produce and verify
> receipts without the AgentLighthouse runtime. Aligns with the Agent Evidence
> Levels (AEL) direction.

A **receipt** is a mediator-signed, hash-chained record of exactly one mediated
decision — a network call, tool call, memory operation, inter-agent message, a
config change, or a kill-switch activation. Receipts form an append-only,
tamper-evident ledger that anyone can verify with the standalone `al-verify`
tool (dependency: `cryptography` only).

## 1. Example

```json
{
  "v": 1,
  "seq": 42,
  "ts": "2026-07-10T12:00:00.000Z",
  "actor": "spiffe://acme/agent/claude-code",
  "action": "mcp_tool_call",
  "target": "tool:send_email",
  "verdict": "block",
  "findings": [
    { "scanner": "tool_policy", "rule_id": "policy.default_deny", "severity": "high", "owasp": "ASI03", "mitre": "T1078" }
  ],
  "block_reason": "TOOL_NOT_ALLOWED",
  "policy_hash": "sha256:...",
  "redaction": { "aws-access-key": 1 },
  "prev_hash": "sha256:...",
  "record_hash": "sha256:...",
  "sig": "ed25519:..."
}
```

## 2. Fields

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `v` | int (=1) | yes | Schema version. |
| `seq` | int ≥ 0 | yes | Monotonic chain sequence number. |
| `ts` | string | yes | RFC 3339 UTC, millisecond precision, trailing `Z`. |
| `actor` | string | yes | SPIFFE-style agent identity. No identity → the request is denied (there is still a receipt, actor names the mediator context). |
| `action` | enum | yes | Closed set (see below). |
| `target` | string | yes | Subject of the action, e.g. `tool:send_email`, a URL, a memory key. |
| `verdict` | enum | yes | `block > strip > warn > ask > allow` (precedence order). |
| `findings` | array | no | Zero or more scanner findings; each has `scanner`, `rule_id`, `severity`, optional `owasp`, `mitre`. |
| `block_reason` | string | no | Fixed machine-readable vocabulary + retry hint; present on non-allow verdicts. |
| `policy_hash` | string | no | `sha256:...` of the policy in force. |
| `redaction` | object | no | Redaction class → integer count. **Counts only; never plaintext.** |
| `session` | string | no | Agent session the decision belongs to (the taint/HITL scope), when one exists — e.g. `mcp:spiffe://acme/agent/claude-code`. Added 2026-07-13; optional fields are additive and backward compatible (§4 hashes whatever fields are present). |
| `latency_ms` | int ≥ 0 | no | Milliseconds from request receipt to this decision, on gateway actions. Added 2026-07-13. |
| `prev_hash` | string | yes | `record_hash` of the previous receipt; genesis = `sha256:` + 64 zeros. |
| `record_hash` | string | yes | See §4. |
| `sig` | string | yes | See §4. |

**Action vocabulary:** `http_forward`, `fetch`, `llm_call`, `mcp_tool_call`,
`mcp_tool_result`, `memory_read`, `memory_write`, `skill_load`, `a2a_message`,
`config_change`, `killswitch`, `remote_exec`, `session_open`, `session_close`,
`permission_request`, `mcp_client_reply`.

> `mcp_client_reply` (added 2026-09-30) covers the agent (the MCP client)
> answering a request the MCP server sent it, such as a
> `sampling/createMessage` result or an elicitation response. The answer is
> DLP-scanned on its way to the server, and an answer to a request the agent
> was never shown is dropped. Additive, like the entries below.

> `remote_exec`, `session_open`, `session_close`, `permission_request`
> (added 2026-08-31, spec v1.1) carry the **remote-execution plane**: a host
> application embedding `al_core` (e.g. access_control) that opens and closes
> authenticated multi-hop sessions, runs catalogued operations on remote
> estates, and files permission requests for gated ones. Additive, like
> `skill_load` below: verification is over the canonical bytes plus the
> signature, so every pre-existing receipt still verifies and an older
> verifier checks the new receipts correctly without knowing the names.

> `skill_load` (added 2026-07-12) covers an **agent instruction file** — a
> `SKILL.md`, `CLAUDE.md`, `.cursorrules` or similar — being screened and pinned
> on load. Adding a member to this enum is **additive and backward compatible**:
> verification is over the canonical bytes plus the signature, so an older
> verifier checks a `skill_load` receipt correctly without knowing the name.
> Consumers that validate against `receipt-v1.schema.json` should take the
> updated schema.

## 3. Canonicalization (JCS, RFC 8785)

Hashing and signing operate on the **canonical form** of the receipt:

1. Serialize with [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785):
   object members sorted by the UTF-16 code units of their keys, no insignificant
   whitespace, `,` and `:` separators, minimal string escaping.
2. **Profile restriction (fail-closed):** receipt values are limited to strings,
   integers, booleans, null, objects, and arrays. Floating-point numbers are
   rejected — every numeric field is an integer, so the subtle ECMAScript number
   formatting rules never apply and canonicalization is unambiguous.

The reference implementation is `al_verify/canonical.py` (~60 lines, no
dependencies beyond the standard library).

## 4. Hash chain & signature

Let `JCS(x)` be the UTF-8 canonical bytes of object `x`.

1. **record_hash** commits to every field except `record_hash` and `sig`
   (including `prev_hash`):

   ```
   record_hash = "sha256:" + hex( SHA-256( JCS( receipt \ {record_hash, sig} ) ) )
   ```

2. **sig** signs the receipt with `record_hash` present but `sig` absent:

   ```
   sig = "ed25519:" + base64( Ed25519_sign( privkey, JCS( receipt \ {sig} ) ) )
   ```

3. **Chain:** `prev_hash` of record *N* equals `record_hash` of record *N−1*.
   The genesis record's `prev_hash` is `sha256:` followed by 64 `0`s.

Because `record_hash` is inside the signed bytes, a valid signature also attests
to the record hash and thus (transitively) to `prev_hash` — so a verified chain
is tamper-evident end to end.

## 5. Verification algorithm

Given a public key and one receipt:

1. Recompute `record_hash` from `JCS(receipt \ {record_hash, sig})`; it must equal
   the stored `record_hash`.
2. Verify the Ed25519 signature over `JCS(receipt \ {sig})`.
3. For a chain: check `prev_hash[N] == record_hash[N-1]`, starting from genesis,
   and that `seq` is contiguous.

Any failure is fatal — the verifier never accepts a receipt it cannot fully
check (fail-closed). Reference: `al_verify/verify.py`; CLI: `al-verify`.

## 6. Storage

- **Canonical:** append-only JSONL, one receipt per line, in `seq` order.
- **Mirror:** SQLite (WAL) for queries only — never a source of truth.
- The chain is re-verified on startup; a break raises an alert.
