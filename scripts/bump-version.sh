#!/usr/bin/env bash
# Cut a release version bump: sync all 4 workspace pyproject.toml versions,
# roll CHANGELOG.md's [Unreleased] section into a dated release section,
# commit, and tag.
#
# The four packages (root, core/, verify/, governance/) are gated together
# by `make release` and released as one unit, so they always carry the same
# version number — this script is the only place that should ever change
# any of them.
#
# Usage:
#   scripts/bump-version.sh <X.Y.Z>
#
# What it does NOT do: push the commit/tag, or cut the GitHub Release.
# Review the diff, then:
#   git push && git push --tags
#   gh release create vX.Y.Z --generate-notes   # (or via the GitHub UI)
# publish-image.yml fires on that release and builds/signs the image.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
  echo "usage: scripts/bump-version.sh <X.Y.Z>" >&2
  exit 1
fi
if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: '${VERSION}' is not a plain semver X.Y.Z (no leading 'v', no suffix)" >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: working tree is not clean — commit or stash first" >&2
  exit 1
fi

if git rev-parse "v${VERSION}" >/dev/null 2>&1; then
  echo "error: tag v${VERSION} already exists" >&2
  exit 1
fi

if ! grep -q '^## \[Unreleased\]' CHANGELOG.md; then
  echo "error: CHANGELOG.md has no [Unreleased] section to roll" >&2
  exit 1
fi

PYPROJECTS=(pyproject.toml core/pyproject.toml verify/pyproject.toml governance/pyproject.toml)

echo "[1/4] pyproject.toml versions -> ${VERSION}"
for f in "${PYPROJECTS[@]}"; do
  # First `version = "..."` line under [project] in each file.
  sed -i "0,/^version = \".*\"/s//version = \"${VERSION}\"/" "${f}"
  echo "  ${f}"
done

echo "[2/4] CHANGELOG.md: [Unreleased] -> [${VERSION}] - $(date +%Y-%m-%d)"
TODAY="$(date +%Y-%m-%d)"
# Insert a fresh empty [Unreleased] skeleton above the section being dated,
# then rename that section's heading.
python3 - "$VERSION" "$TODAY" <<'PY'
import re, sys, pathlib
version, today = sys.argv[1], sys.argv[2]
p = pathlib.Path("CHANGELOG.md")
text = p.read_text(encoding="utf-8")
skeleton = (
    "## [Unreleased]\n\n"
    "### Added\n### Changed\n### Fixed\n### Security\n\n"
)
marker = "## [Unreleased]\n"
if marker not in text:
    sys.exit("no [Unreleased] marker found")
text = text.replace(marker, skeleton + f"## [{version}] - {today}\n", 1)
p.write_text(text, encoding="utf-8")
PY

echo "[3/4] commit"
git add "${PYPROJECTS[@]}" CHANGELOG.md
git commit -m "Release v${VERSION}"

echo "[4/4] tag v${VERSION}"
git tag -a "v${VERSION}" -m "v${VERSION}"

cat <<EOF

Done. Not pushed yet — review, then:
  git push && git push --tags
  gh release create v${VERSION} --generate-notes
EOF
