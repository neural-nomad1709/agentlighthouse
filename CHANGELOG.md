# Changelog

All notable changes to AgentLighthouse are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/).

The root `pyproject.toml` version and the three workspace members
(`core/`, `verify/`, `governance/`) move together as one release version —
see `scripts/bump-version.sh`. The released git tag (`vX.Y.Z`) is the
source of truth; it is what `publish-image.yml` reads to tag the image.

## [Unreleased]

### Added
### Changed
### Fixed
### Security

## [0.2.0] - 2026-09-27

### Added
- HITL approvals are served: approvals API plus `al hitl` CLI verbs.
- HITL approvals and taint marks are persisted and rehydrated on boot;
  HitlGate requests carry detail and session, persisted and surfaced.
- Opt-in detect-secrets adapter behind the `Scanner` protocol
  (`al-core[scanners]` + `scanner.detect_secrets.enabled: true`).
- `al_core.embed` embedding facade.
- Receipt spec v1.1: additive remote-execution actions (`remote_exec`,
  `session_open`, `session_close`, `permission_request`).
- `CHANGELOG.md`, `scripts/bump-version.sh`, and `make bump-version` for
  coordinated release versioning across the workspace (root + `core/` +
  `verify/` + `governance/` move as one version, tagged `vX.Y.Z`).

### Changed
- `.gitignore`: anchor `/.internal/` to the repo root; ignore `/paper/*`
  build output.
- `README.md`: refresh test counts (711 total / 699 passing), document the
  detect-secrets adapter, drop "pending trademark clearance".
- Root `pyproject.toml` version aligned with the workspace members (was
  `0.0.0`); `Makefile` `IMAGE` tag now tracked by `bump-version.sh`.

### Fixed
- Per-actor tool-call budgets are enforced at the ActionGate (previously
  declared but never checked); budget is consumed only after all gates pass,
  `0` means disabled, and the window is locked.

### Security
- AL-0 review fixes: adapter fail-opens closed, approvals tenancy enforced,
  deadline hardening.

## [0.1.0] - 2026-09-27

- Initial tracked version: egress gate, content gate, action gate, memory
  guard, signed evidence receipts; HITL approvals; per-actor tool-call
  budgets; A2A card/session hardening; standalone `al-verify` receipt
  verification.
