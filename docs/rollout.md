# Rollout: audit -> balanced -> strict

The three modes are shipped configs (`configs/audit.yaml`, `balanced.yaml`,
`strict.yaml`) selected with `--config` (or by editing your site copy —
explicit YAML beats environment variables). The mode is an enforcement
posture, not a feature switch: promote deliberately, with evidence.

## What each mode does

| | audit | balanced (default) | strict |
|---|---|---|---|
| Scan verdicts (block/strip) | observed + receipted, not enforced | enforced | enforced |
| Permissive settings (disable a scanner, `require_identity: false`) | allowed — the ONLY mode where they are | refused at config validation | refused at config validation |
| Egress allowlist | as configured | default-deny (`allow_hosts: []`) | default-deny, HTTPS only (`allow_ports: [443]`) |
| Rate / data budget per domain | as configured | 10 rps / 10 MiB per day | 5 rps / 5 MiB per day |
| Fetch limits | as configured | 5 MiB, 3 redirects | 1 MiB, 1 redirect |
| Entropy thresholds | as configured | 4.0 / 3.5 | 3.5 / 3.0 (more sensitive) |
| Attestation evidence level | capped at AEL-1 (audit cannot claim enforcement) | AEL-2+ | AEL-2+ |

## What stays enforced even in audit mode

Audit mode observes scan verdicts. It does not turn the plane off, and the
following enforce in every mode — by design, with tests:

- **Engine failure blocks.** A crashed or timed-out scanner denies
  (`SCANNER_FAILED` / `SCANNER_TIMEOUT`) even in audit — a gate that cannot
  scan cannot claim to observe.
- **Guard-native checks.** Memory protected-key writes, size caps, and
  integrity baselines are not scans; they always enforce.
- **Key policy.** Missing key in prod, or permissions looser than 0600:
  refuse to start.
- **Signed rules only.** An unsigned or tampered learned-rule bundle is
  refused at boot in every mode.
- **The kill switch.** Engaged means deny-all, regardless of mode.
- **Evidence.** Every decision is receipted and hash-chained in every mode —
  audit mode is how you collect the tuning corpus.

## The promotion path

### Stage 1 — audit (1-2 weeks against real workloads)

1. Deploy with `configs/audit.yaml` (pilot install: `make pilot`, then point
   the services at the audit config).
2. Run the real agent workloads through the plane. Nothing user-visible
   changes; every would-be verdict is receipted.
3. Tune from evidence, not intuition:
   - dashboard trends and verdict breakdowns (`al dashboard`);
   - `al export --verdict block` — review every would-block: attack or
     false positive?
   - `al learn mine` — repeated blocked targets propose candidate rules for
     the human review gate.
4. Exit criteria: a week with no false positives you have not either fixed
   (allowlist, threshold, policy rule) or accepted.

### Stage 2 — balanced (the default production posture)

1. Switch the config to `configs/balanced.yaml` (or your tuned site copy).
   Restart; the config change lands as a signed receipt.
2. Verify the posture is now claimable: export a signed attestation and
   check the computed level — `al-gov attest export <org>` must report
   AEL-2 or higher (enforcing). Audit mode structurally cannot produce this.
3. Watch week one like a hawk: `BLOCKED` receipts are now user-visible
   denials. The blueprint's success metric is zero workflow breakage in
   balanced mode — only a real workload can prove it.

### Stage 3 — strict (high-sensitivity workloads)

1. Strict tightens thresholds and narrows egress (HTTPS only, 1 redirect,
   1 MiB fetches, half the rate/data budgets). Expect more friction; apply
   it where the data warrants it — it can be per-deployment, not fleet-wide.
2. Re-run the tuning loop: what balanced tolerated, strict may block.

## Promotion checklist (each stage)

- [ ] `uv run pytest -q` green on the build you are promoting
- [ ] `make demo` passes (the release gate)
- [ ] `al check --config <new config>` exits 0 (fail-closed validation)
- [ ] `/healthz` healthy after restart; chain verifies
  (`al-verify data/ledger.jsonl --pubkey keys/mediator_ed25519.pub`)
- [ ] signed attestation exported before AND after — the posture change is
  itself evidence
- [ ] the kill-switch drill has been run by the on-call operator this stage
