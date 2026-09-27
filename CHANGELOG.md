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
- `CHANGELOG.md`, `scripts/bump-version.sh`, and `make bump-version` for
  coordinated release versioning across the workspace (root + `core/` +
  `verify/` + `governance/` move as one version, tagged `vX.Y.Z`).

### Changed
- `.gitignore`: anchor `/.internal/` to the repo root; ignore `/paper/*`
  build output.
- `README.md`: drop "pending trademark clearance" from the working-name note.

### Fixed
### Security

## [0.1.0] - 2026-09-27

- Initial tracked version: egress gate, content gate, action gate, memory
  guard, signed evidence receipts; HITL approvals; per-actor tool-call
  budgets; A2A card/session hardening; standalone `al-verify` receipt
  verification.
