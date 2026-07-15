# Security Policy

## Reporting a vulnerability

Report it privately through [GitHub's private vulnerability reporting](https://github.com/neural-nomad1709/agentlighthouse/security/advisories/new)
— the repository's **Security** tab, then **Report a vulnerability**. Please do
not open a public issue for a suspected vulnerability.

Include what you need to make the finding reproducible: the version or commit,
the configuration profile (`audit` / `balanced` / `strict`), and the smallest
input that demonstrates it. If the finding produced receipts, attach them — they
are signed, so they are evidence.

Expect an acknowledgement within a few days. This is a single-maintainer project,
so please size your expectations accordingly.

## Known gaps

Before reporting, check whether what you found is already named in the
**"What this does NOT do"** section of the [README](README.md). The known and
documented limits are: the baseline scanners are regex and heuristics rather
than the named ML engines; A2A sender identity is asserted rather than proven;
the forward proxy cannot see inside a TLS CONNECT tunnel; and L0 nftables
enforcement has not been validated on bare-metal Linux.

A gap that is already documented is not a vulnerability report. A gap that is
documented but **worse than described** very much is, and is worth telling me
about.

## What counts as a vulnerability here

The security claims this project makes are the ones worth attacking:

- **The choke-point holds.** An agent reaching the network without passing
  through the mediator is a critical finding.
- **The control plane is unreachable from the agent network.**
- **Fail-closed.** Any input that makes a gate fail *open* — a scanner crash,
  timeout, or malformed payload that results in `allow` rather than `block` — is
  a vulnerability.
- **Evidence is tamper-evident.** A forged or altered receipt that still passes
  `al-verify` is a critical finding.
- **Redaction holds.** Plaintext secrets or PII appearing in the ledger is a
  vulnerability; receipts are meant to carry counts and classes only.
- **A learned rule cannot loosen the gate.** Any path that loads an unsigned or
  tampered rule bundle is a critical finding.

## Verifying a release

Container images are signed with [cosign](https://github.com/sigstore/cosign) and
carry an SPDX SBOM attestation:

```bash
cosign verify <image>
cosign verify-attestation --type spdxjson <image>
```

Evidence produced by a running mediator can be verified with no trust in this
codebase at all, using the standalone verifier:

```bash
al-verify data/ledger.jsonl --pubkey keys/mediator_ed25519.pub
```
