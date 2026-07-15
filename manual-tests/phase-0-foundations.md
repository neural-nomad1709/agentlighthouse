# Phase 0 manual tests — Foundations (evidence-first)

What you verify: workspace initialization, fail-closed config validation,
signed hash-chained receipts, independent verification, tamper evidence, and
the SQLite evidence mirror.

## Environment setup

1. Complete the [common setup](README.md#common-environment-setup).
2. Start from a clean ledger (see "Resetting to a clean slate" in the README)
   so receipt counts below match exactly.

## Test data preparation

Create an intentionally invalid config for test 0.2 (a copy of the balanced
config plus a key the schema forbids):

- Windows (PowerShell):

  ```powershell
  Copy-Item configs/balanced.yaml configs/_bad_test.yaml
  Add-Content configs/_bad_test.yaml "unknown_key: 1"
  ```

- Linux/macOS (bash):

  ```bash
  cp configs/balanced.yaml configs/_bad_test.yaml
  echo "unknown_key: 1" >> configs/_bad_test.yaml
  ```

## Tests

### 0.1 Version and workspace

1. Run `uv run al version`.
2. Run `uv run al init --config configs/balanced.yaml` a second time.

Expected: a version string prints; the re-run reports the `.env` and signing
key `already exists — leaving it` (init never overwrites keys or tokens).

### 0.2 Config is an enforcement boundary (fail-closed)

1. Run `uv run al check --config configs/balanced.yaml`.
2. Run `uv run al check --config configs/_bad_test.yaml`.

Expected: step 1 succeeds (`config OK`, exit 0). Step 2 fails with a
non-zero exit code naming `unknown_key` — unknown keys are refused
(`extra="forbid"`), never ignored.

### 0.3 Runtime boots healthy and verifies its own chain

1. Run `uv run al healthz --config configs/balanced.yaml`.

Expected: `status: healthy`, config mode `balanced`, and a chain-verification
result in the payload. Exit 0.

### 0.4 Receipts are produced, chained, and independently verifiable

1. Produce two mediated decisions (guarded memory writes are the simplest
   local source of receipts):

   ```
   uv run al memory put notes/first "hello"
   uv run al memory put notes/second "world"
   ```

2. Verify the ledger with the standalone verifier:

   ```
   uv run al-verify data/ledger.jsonl --pubkey keys/mediator_ed25519.pub
   ```

Expected: both writes exit 0; the verifier prints
`chain of N receipt(s) verified from genesis  OK` (N >= 2). `al-verify` is a
separate package needing only `cryptography` — this is the portability claim.

### 0.5 Tamper evidence

Work on a copy — never edit the real ledger.

1. Copy the ledger:
   - Windows: `Copy-Item data/ledger.jsonl $env:TEMP/tampered.jsonl`
   - Linux: `cp data/ledger.jsonl /tmp/tampered.jsonl`
2. Open the copy in an editor and change any single character inside any
   line's `"target"` or `"action"` value. Save.
3. Verify the copy:
   - Windows: `uv run al-verify $env:TEMP/tampered.jsonl --pubkey keys/mediator_ed25519.pub`
   - Linux: `uv run al-verify /tmp/tampered.jsonl --pubkey keys/mediator_ed25519.pub`

Expected: verification FAILS with a non-zero exit code, naming the record
whose hash or signature no longer checks out. Re-running against the real
`data/ledger.jsonl` still passes.

### 0.6 SQLite mirror agrees with the ledger

1. Run `uv run al db init` (creates the mirror if absent).
2. Run `uv run al db stats`.

Expected: event totals and per-action counts consistent with what you ran in
0.4 (at least two `memory_write` events). The JSONL ledger remains canonical;
the mirror is a query surface.

## Cleanup

```
Remove-Item configs/_bad_test.yaml        # Linux: rm configs/_bad_test.yaml
```

Optionally reset `data/` for the next phase document.
