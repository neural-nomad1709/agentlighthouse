# agentlighthouse-verify

**Standalone verifier for AgentLighthouse evidence.**

[AgentLighthouse](https://github.com/neural-nomad1709/agentlighthouse) is a
security mediator for AI agents. It writes a signed receipt for every decision
it takes. This package checks those receipts, and it does so without the
mediator: it does not import the runtime, and its only dependency is
[`cryptography`](https://pypi.org/project/cryptography/).

That separation is the point. An auditor, a customer or a regulator can verify
the evidence with a small tool they can read end to end, and does not have to
trust the operator's binary.

- **Source:** <https://github.com/neural-nomad1709/agentlighthouse>
- **Receipt specification:** [receipt-v1](https://github.com/neural-nomad1709/agentlighthouse/blob/main/spec/receipt-v1.md)
- **License:** MIT
- **Python:** 3.12 or newer

## Contents

- [Install](#install)
- [Verify a ledger](#verify-a-ledger)
- [What can be verified](#what-can-be-verified)
- [What verification checks](#what-verification-checks)
- [Command line](#command-line)
- [The receipt format](#the-receipt-format)
- [Trust model](#trust-model)
- [Related packages](#related-packages)
- [License](#license)

## Install

```bash
pip install agentlighthouse-verify
```

This installs one command, `al-verify`.

## Verify a ledger

You need two files from the operator: the ledger and the mediator's public
key.

```bash
al-verify ledger.jsonl --pubkey mediator_ed25519.pub
```

```
chain of 11 receipt(s) verified from genesis
OK
```

The exit code is `0` when everything verifies and non-zero when anything does
not, so the command can gate a pipeline.

## What can be verified

| Input | What it is |
|---|---|
| A receipt (`.json`) | One mediated decision |
| A ledger (`.jsonl`, or a JSON array) | The full chain of receipts, from the first one |
| A posture attestation | A signed per-organization summary of posture and evidence over a period |
| A rule bundle | A signed set of detection rules; the mediator refuses to load an unsigned or altered one |

## What verification checks

Verification is fail-closed. Any one failure fails the whole run.

1. **The record hash.** The receipt is canonicalized with RFC 8785 (JCS) and
   hashed with SHA-256. The result must equal the `record_hash` the receipt
   carries, so a changed field is detected.
2. **The signature.** `sig` must be a valid Ed25519 signature over that hash
   by the mediator key you supplied.
3. **The chain.** Each receipt's `prev_hash` must equal the previous receipt's
   `record_hash`, and sequence numbers must be contiguous from genesis. A
   removed, reordered or inserted receipt is detected.

The canonicalization and the hash chain are implemented in this package from
the specification, with no third-party code, so the trust surface stays small
enough to audit.

## Command line

```
al-verify [--pubkey PUBKEY] [--quiet] [--version] receipt
```

| Argument | Meaning |
|---|---|
| `receipt` | Path to a receipt `.json`, a `.jsonl` ledger, an attestation or a rule bundle |
| `--pubkey` | The mediator's public key: a file, or the key inline as hex. Default: `keys/mediator_ed25519.pub` |
| `--quiet` | Print only the final verdict |
| `--version` | Print the version |

## The receipt format

A receipt records exactly one decision:

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

- `actor` is the identity the decision is bound to.
- `action` comes from a closed vocabulary. The vocabulary grows additively, so
  this verifier still checks a receipt that carries a newer action.
- `redaction` holds counts per class. A receipt never carries the secret or
  the personal data that was redacted.

The format is specified, with a JSON Schema, in
[receipt-v1](https://github.com/neural-nomad1709/agentlighthouse/blob/main/spec/receipt-v1.md).
The specification is MIT-licensed, so third parties can produce and verify
receipts without this code.

## Trust model

Verification proves that the receipts were signed by the holder of the key you
supplied and that the chain has not been altered since. It follows that:

- **The public key must reach you through a channel you trust.** A ledger and
  a key handed over together by the same party prove only that they match.
- **A verified chain is complete from genesis to its last receipt.** It does
  not show that the mediator saw every action an agent took. That depends on
  how the mediator is deployed: see the
  [architecture document](https://github.com/neural-nomad1709/agentlighthouse/blob/main/docs/architecture.md).
- **A posture attestation names the chain head it was cut from**, so it can be
  tied back to a ledger you have verified.

## Related packages

| Package | What it is |
|---|---|
| [agentlighthouse-core](https://pypi.org/project/agentlighthouse-core/) | The mediator that produces the receipts. It depends on this package. |
| [agentlighthouse-governance](https://pypi.org/project/agentlighthouse-governance/) | Organizations, role-based access, budgets and signed posture attestation. |

## License

MIT. See the `LICENSE` file shipped with this package.
