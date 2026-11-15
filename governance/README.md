# agentlighthouse-governance

**Multi-organization governance for AgentLighthouse.**

[AgentLighthouse](https://github.com/neural-nomad1709/agentlighthouse) is a
security mediator for AI agents that signs a receipt for every decision it
takes. This package adds what a team running more than one agent fleet needs
on top of it: organizations as tenants, role-based access, per-organization
budgets with cost reporting, and a **signed posture attestation** whose
evidence level is computed from the ledger.

It provides the `al-gov` command line and a governed control-plane service.

- **Source and full documentation:** <https://github.com/neural-nomad1709/agentlighthouse>
- **License:** MIT
- **Python:** 3.12 or newer

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Organizations](#organizations)
- [Users and roles](#users-and-roles)
- [Posture attestation](#posture-attestation)
- [Budgets and cost](#budgets-and-cost)
- [The governed control plane](#the-governed-control-plane)
- [Where tenant isolation is enforced](#where-tenant-isolation-is-enforced)
- [Command reference](#command-reference)
- [Related packages](#related-packages)
- [License](#license)

## Install

```bash
pip install agentlighthouse-governance
```

This installs `al-gov`, and with it the mediator
([agentlighthouse-core](https://pypi.org/project/agentlighthouse-core/),
command `al`) and the standalone verifier
([agentlighthouse-verify](https://pypi.org/project/agentlighthouse-verify/),
command `al-verify`).

The governance layer runs on the control host, next to the control plane. It
is not part of the agent-facing data plane.

## Quick start

Start from a workspace created with `al init`.

```bash
al-gov org create acme                                # create a tenant
al-gov user add alice@acme --org acme --role admin    # prints the user's token once

al-gov attest export acme > acme.attest.json          # signed posture attestation
al-gov attest verify acme.attest.json                 # verified, with its evidence level

al-gov cost --org acme                                # today's spend per virtual key
al-gov serve                                          # governed control plane and dashboard
```

## Organizations

An organization is a tenant. Its slug is the organization segment of its
agents' identities:

```
spiffe://<org>/agent/<name>
```

An agent identified as `spiffe://acme/agent/research-agent` belongs to the
organization `acme`, and its receipts are that organization's evidence. A slug
is made of lowercase letters, digits, `.`, `_` and `-`.

```bash
al-gov org create acme
al-gov org list
```

## Users and roles

| Role | Capabilities |
|---|---|
| `admin` | View and verify evidence, resolve approvals, configure, export attestations |
| `operator` | View and verify evidence, resolve approvals |
| `viewer` | View and verify evidence |

A user belongs to one organization and sees only that organization's evidence.
A fleet administrator has no organization and sees across all of them; that
scope is available to administrators only.

```bash
al-gov user add alice@acme --org acme --role admin
al-gov user list
al-gov user revoke alice@acme
```

A token is printed once, when the user is added. It is stored hashed and
cannot be recovered. A revoked token stops authenticating immediately,
including against a control plane that is already running.

## Posture attestation

An attestation is a signed statement about one organization over a period:

- its posture (mode, environment, whether the mediator is enforcing, whether
  the egress self-test is enforced, and the configuration hash)
- its evidence, counted by verdict, action, block reason and OWASP Agentic
  risk
- the head of the receipt chain it was cut from

It is signed with the mediator's key and can be verified by anyone holding the
public key, using the standalone verifier:

```bash
al-gov attest export acme > acme.attest.json
al-verify acme.attest.json --pubkey keys/mediator_ed25519.pub
```

### The evidence level is computed

The attestation carries an Agent Evidence Level. It is derived from the
evidence and can only be reduced by a failing condition, so a deployment
cannot claim a level it has not earned.

| Level | Condition |
|---|---|
| `AEL-0` | The chain does not verify. Nothing in the attestation is trusted. |
| `AEL-1` | Every decision is signed and the chain verifies from genesis. |
| `AEL-2` | AEL-1, and the mediator enforces. A deployment in `audit` mode cannot reach this level. |
| `AEL-3` | AEL-2, and the egress choke-point self-test is enforced. |

Exporting an attestation before and after a change of mode turns the change
itself into evidence.

## Budgets and cost

Each organization can carry daily request and token budgets. A request over
budget is refused by the mediator.

`al-gov cost` reports the day's usage per virtual key, for one organization or
for the whole fleet:

```bash
al-gov cost --org acme
al-gov cost --org acme --usd-per-mtok 3.0     # price it with a blended rate
```

Cost is derived from recorded usage. When no rate is supplied the report gives
no dollar figure, because an unknown price is not zero.

## The governed control plane

`al-gov serve` runs the control plane with the organization directory as its
authenticator, and serves the evidence dashboard and the governance API.

```bash
al-gov serve --host 127.0.0.1 --port 8888
```

Every read is scoped to the caller's organization. Asking for a receipt that
belongs to another tenant returns "not found" and never "forbidden", because
confirming that a receipt exists would itself leak information.

Bind the service to the control network only. Agents must have no route to it.

## Where tenant isolation is enforced

Isolation is enforced in the mediator, `agentlighthouse-core`, which never
imports this package. The governance layer supplies the directory of
organizations and users, and the core applies the scope to every evidence
read. A defect in this layer can therefore narrow what a caller sees and
cannot widen it.

## Command reference

| Command | Purpose |
|---|---|
| `al-gov org create <slug>` | Create a tenant |
| `al-gov org list` | List tenants |
| `al-gov user add <subject> --org <slug> --role <role>` | Add a user and print its token once |
| `al-gov user list` | List users, never their tokens |
| `al-gov user revoke <subject>` | Revoke a user |
| `al-gov attest export <slug>` | Export a signed posture attestation |
| `al-gov attest verify <file>` | Verify an attestation |
| `al-gov cost [--org <slug>]` | Report spend per virtual key |
| `al-gov serve` | Serve the governed control plane |

Run any command with `--help` for its options.

## Related packages

| Package | What it is |
|---|---|
| [agentlighthouse-core](https://pypi.org/project/agentlighthouse-core/) | The mediator: proxies, scanners, policy engine, evidence ledger. |
| [agentlighthouse-verify](https://pypi.org/project/agentlighthouse-verify/) | The standalone verifier for receipts and attestations. |

## License

MIT. See the `LICENSE` file shipped with this package.
