# Phase 7 manual tests — Learning loop + A2A mediation (ASI07)

What you verify: the full learning round-trip (blocks -> mined candidate ->
human-signed bundle -> generated regression test -> enforced rule that
inherits evasion folding; unsigned bundles refused), and Demo 3's A2A
interceptions (card poisoning, rug-pull drift, session smuggling).

## Environment setup

1. Complete the [common setup](README.md#common-environment-setup).
2. Start from a clean `data/` (README reset steps) so exactly the seeded
   blocks are in the ledger.
3. You need the agent identity flow from Phase 1: issue one with
   `uv run al identity issue acme tester` and record the token (`<TOKEN>`).
4. Two terminals (gateway + requests) for the seeding step only.

## Test data preparation

Seed four real blocks against one hostile host. Start the gateway
(`uv run al gateway --host 127.0.0.1 --config configs/balanced.yaml`), then:

```
curl.exe "http://127.0.0.1:8443/fetch?url=https://collector.evil.example/beacon-1" -H "X-AL-Identity: spiffe://acme/agent/tester" -H "Authorization: Bearer <TOKEN>"
curl.exe "http://127.0.0.1:8443/fetch?url=https://collector.evil.example/beacon-2" -H "X-AL-Identity: spiffe://acme/agent/tester" -H "Authorization: Bearer <TOKEN>"
curl.exe "http://127.0.0.1:8443/fetch?url=https://collector.evil.example/beacon-3" -H "X-AL-Identity: spiffe://acme/agent/tester" -H "Authorization: Bearer <TOKEN>"
curl.exe "http://127.0.0.1:8443/fetch?url=https://collector.evil.example/beacon-4" -H "X-AL-Identity: spiffe://acme/agent/tester" -H "Authorization: Bearer <TOKEN>"
```

Each returns `403 HOST_NOT_ALLOWED` (default-deny; the domain never
resolves — no traffic leaves). Stop the gateway (Ctrl+C).

Also confirm the baseline: `uv run al scan "collector.evil.example"` —
verdict `allow`, exit 0. The baseline scanners do not know this host yet.

## Tests

### 7.1 Mining proposes; nothing is enforced

```
uv run al learn mine
```

Expected: one candidate, `learned.host.collector_evil_example`, pattern
`collector\.evil\.example`, action block, rationale "blocked 4 times",
citing the four receipt seqs. Receipts hold no plaintext by design, so the
miner works from blocked TARGETS (and the memory quarantine) — the candidate
is inert: re-run the baseline scan above; still `allow`.

### 7.2 The human review gate signs the bundle and generates its test

```
uv run al learn approve --rule learned.host.collector_evil_example --by you@example.com --bundle-id manual-b1
```

Expected: a signed bundle at `data/rules/manual-b1.json` and a generated
regression test under `tests/learned/` (one test pinning the rule to the
sample that taught it, one asserting the bundle still verifies).

### 7.3 The bundle verifies standalone — and tamper is refused

```
uv run al learn verify data/rules/manual-b1.json
uv run pytest tests/learned -q
```

Expected: `rule bundle 'manual-b1' verified (1 rule(s), approved by
'you@example.com')`; the generated tests pass.

Now tamper: edit `data/rules/manual-b1.json` and change one character inside
the pattern. Re-run `uv run al learn verify data/rules/manual-b1.json` —
expected: verification FAILS, exit 1. Undo the edit (or re-approve) before
continuing.

### 7.4 The signed rule enforces through the normal scanner seam

1. Create an enforcing config:

   ```
   Copy-Item configs/balanced.yaml configs/_manual_p7.yaml     # Linux: cp
   ```

   Append to `configs/_manual_p7.yaml`:

   ```yaml
   learn:
     rule_bundle: data/rules/manual-b1.json
   ```

2. Scan before/after, plus an evasion-folded variant:

   ```
   uv run al scan "please visit collector.evil.example now"
   uv run al scan -c configs/_manual_p7.yaml "please visit collector.evil.example now"
   uv run al scan -c configs/_manual_p7.yaml "c0llector.evil.example"
   ```

Expected: default config `allow` (exit 0); with the bundle loaded, `block`
naming rule `learned.host.collector_evil_example` (exit 3) — including the
leetspeak variant, because a learned rule runs over every L2 normalization
variant like any other scanner.

### 7.5 An unsigned bundle can never board

Tamper the bundle again (as in 7.3, leave it tampered), then:

```
uv run al healthz --config configs/_manual_p7.yaml
```

Expected: the runtime REFUSES to boot (fail-closed, `RULE_BUNDLE_UNSIGNED`)
— a tampered bundle is not loaded with a warning, it is not loaded at all.
The learning loop can teach the plane to block, never to allow. Restore the
bundle (re-approve as in 7.2) or remove the `learn:` block afterwards.

### 7.6 Demo 3 — A2A interceptions

```
make demo-a2a
```

(Equivalent without make: `uv run python examples/a2a-lab/demo.py`.)

Expected transcript, exit 0:

- [1] alice and bob open a session; bob's Agent Card is pinned
- [2] bob's card swapped for a poisoned one -> `A2A_CARD_POISONED`
  (the payload is never even considered)
- [3] the card quietly gains a wire_transfer skill -> `A2A_CARD_DRIFT`
  (rug-pull)
- [4] mallory replays alice's session id -> `A2A_SESSION_SMUGGLED`
- [5] a clean peer message still taints the receiving session
  (untrusted ingestion)
- [6] all interceptions ASI07-tagged, no exfil host in the ledger;
  `chain of N receipt(s) verified from genesis  OK`

### 7.7 Evidence check

```
uv run al-verify data/ledger.jsonl --pubkey keys/mediator_ed25519.pub
```

Expected: OK.

## Cleanup

The generated regression test asserts the bundle verifies — remove BOTH
together or the suite will fail on the orphaned test:

```
Remove-Item tests/learned/test_learned_manual_b1.py, data/rules/manual-b1.json, configs/_manual_p7.yaml
```

(Linux: `rm tests/learned/test_learned_manual_b1.py data/rules/manual-b1.json configs/_manual_p7.yaml`)

Then confirm the suite is still green: `uv run pytest -q`.
