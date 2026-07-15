#!/usr/bin/env bash
# Release packaging (Phase 8): build the image, generate its SBOM, sign it,
# and attach the SBOM as a signed attestation.
#
# Requires: docker, syft, cosign — and push access to the registry in IMAGE
# (cosign signs by registry digest; a local-only image cannot be signed).
#
# Usage:
#   scripts/release-image.sh [IMAGE]            # default: agentlighthouse/al-core:0.1.0
#
# Signing identity:
#   COSIGN_KEY=cosign.key scripts/release-image.sh ...   # key-based
#   (unset)                                              # keyless (Sigstore OIDC)
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="${1:-agentlighthouse/al-core:0.1.0}"
SBOM_DIR="${SBOM_DIR:-dist}"
SBOM="${SBOM_DIR}/al-core.spdx.json"

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required — $2" >&2; exit 1; }; }
need docker "https://docs.docker.com/engine/install/"
need syft   "https://github.com/anchore/syft"
need cosign "https://github.com/sigstore/cosign"

echo "[1/4] build ${IMAGE}"
docker build -t "${IMAGE}" .

echo "[2/4] SBOM (SPDX JSON) -> ${SBOM}"
mkdir -p "${SBOM_DIR}"
syft "docker:${IMAGE}" -o spdx-json > "${SBOM}"

echo "[3/4] push ${IMAGE} (cosign signs the registry digest)"
docker push "${IMAGE}"
DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' "${IMAGE}")"

echo "[4/4] cosign sign + attest SBOM on ${DIGEST}"
if [ -n "${COSIGN_KEY:-}" ]; then
  cosign sign --yes --key "${COSIGN_KEY}" "${DIGEST}"
  cosign attest --yes --key "${COSIGN_KEY}" --predicate "${SBOM}" --type spdxjson "${DIGEST}"
else
  cosign sign --yes "${DIGEST}"
  cosign attest --yes --predicate "${SBOM}" --type spdxjson "${DIGEST}"
fi

echo
echo "signed: ${DIGEST}"
echo "SBOM:   ${SBOM} (also attached as a signed attestation)"
echo "verify:"
echo "  cosign verify ${DIGEST}"
echo "  cosign verify-attestation --type spdxjson ${DIGEST}"
