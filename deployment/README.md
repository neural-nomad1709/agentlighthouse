# Deployment guides

Three deployments, one per directory, each with step-by-step instructions
for both Windows and Linux.

| Tier | Guide | Users | Tenancy | Runs where | Evidence store |
|------|-------|-------|---------|------------|----------------|
| Dev / community | [dev-community/](dev-community/README.md) | up to 2 | single-tenant | on-premise (workstation or laptop) | SQLite |
| Mid-size | [mid-size/](mid-size/README.md) | up to 10 | single-tenant (multi-org optional) | on-premise or self-managed cloud VM | SQLite (one writer per plane) |
| Enterprise | [enterprise/](enterprise/README.md) | 10+ / multiple teams | multi-tenant (orgs, RBAC, signed attestation) | on-premise or self-managed private cloud, Linux | Postgres mirror (concurrent writers) |

A fourth guide is not a tier: [systemd/](systemd/README.md) runs the mediator
natively on one Linux host, with the agent account confined by nftables, for
when agents cannot run in containers.

## Tenancy, cloud, and on-premise — stated plainly

- **Every tier is self-hosted.** AgentLighthouse runs on infrastructure you
  control: on-premise hardware, or cloud VMs/instances that you manage
  ("cloud" here means your IaaS, not a vendor-hosted SaaS — none exists).
- **Single-tenant by default.** The open core works with no user directory:
  the admin token is a fleet admin, and all evidence lives in one scope.
- **Multi-tenancy is the governance layer** (`governance/`; MIT, like the rest
  of the workspace): orgs,
  roles (admin/operator/viewer), org-scoped evidence reads
  enforced in the core, per-org budgets, and signed per-org posture
  attestations. The enterprise guide turns it on; the mid-size guide shows
  the optional single-org variant.

## Platform reality (read before choosing Windows)

- **Linux is the production platform.** Two enforcement properties need it:
  secrets delivered with sane file modes (`/run/secrets`, uid 10001, mode
  0400 — Windows bind mounts report 0777 and the fail-closed key policy
  refuses, correctly), and L0 nftables enforcement on agent hosts.
- **Windows is a first-class development and evaluation platform.** The full
  suite, all three demos, the native gateway, and the Docker Desktop
  topology (with a dev-grade auto-generated key on the Linux-native volume)
  all run on Windows — that is exactly the dev-community tier.

## Hardening status

Hardening and packaging are in place: the gVisor runtime profile
(`docker-compose.gvisor.yml`), a hardening baseline pinned by test
(`tests/test_hardening.py`), SBOM generation and cosign-signed images
(`make sbom` / `make sign`), and the probe-gated one-command pilot install
(`make pilot`).

Start every deployment in audit mode against your own workload: the
enforcement gates are tested, but the false-positive rate depends on the
workload and no figure is published for it. The README's "What This Does Not
Do" section is the list of what is and is not covered.
