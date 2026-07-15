#!/usr/bin/env bash
# One-command pilot install (Linux/macOS): workspace -> keys -> suite ->
# release gate -> sealed Docker topology, verified end to end.
#
#   scripts/pilot-install.sh          # or: make pilot
#
# Windows: scripts/pilot-install.ps1 (same flow).
set -euo pipefail
cd "$(dirname "$0")/.."

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required — $2" >&2; exit 1; }; }
need uv     "https://docs.astral.sh/uv/"
need docker "https://docs.docker.com/engine/install/"

echo "[1/6] install the workspace (uv sync)"
uv sync

echo "[2/6] initialize keys + workspace"
uv run al init --config configs/balanced.yaml
if [ ! -f keys/admin_api_token ]; then
  uv run python -c "import secrets,sys;sys.stdout.write(secrets.token_urlsafe(32))" > keys/admin_api_token
  chmod 600 keys/admin_api_token
  echo "wrote keys/admin_api_token"
fi

echo "[3/6] test suite"
uv run pytest -q

echo "[4/6] release gate (tool-response injection blocked on all 3 MCP transports)"
uv run python examples/tool-response-injection/demo.py

echo "[5/6] sealed topology (docker compose up)"
docker compose up -d --build

echo "[6/6] verify the topology proofs"
for svc in agent-selftest agent-control-probe; do
  cid="$(docker compose ps -aq "${svc}")"
  for _ in $(seq 1 60); do
    state="$(docker inspect -f '{{.State.Status}}' "${cid}")"
    [ "${state}" = "exited" ] && break
    sleep 2
  done
  code="$(docker inspect -f '{{.State.ExitCode}}' "${cid}")"
  if [ "${code}" != "0" ]; then
    echo "FAIL: ${svc} exited ${code} — the topology did not prove itself; do not run agents on it" >&2
    exit 1
  fi
  echo "  ${svc}: proof held (exit 0)"
done

health="$(uv run python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8443/healthz',timeout=10).status)")"
if [ "${health}" != "200" ]; then
  echo "FAIL: data plane /healthz returned ${health}" >&2
  exit 1
fi
echo "  data plane: healthy (chain verified at boot)"

cat <<'EOF'

pilot install complete.
  data plane   http://127.0.0.1:8443   (fetch + LLM reverse proxy + POST /mcp)
  control      http://127.0.0.1:8898   (kill switch + dashboard; token: keys/admin_api_token)
next steps:
  docker compose exec al-core al vkey issue <user> --max-requests 500
  docker compose exec al-core al identity issue <org> <agent>
  deployment guides: deployment/README.md   rollout modes: docs/rollout.md
EOF
