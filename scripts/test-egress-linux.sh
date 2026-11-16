#!/usr/bin/env bash
# Run the Linux-only L0 enforcement tests (tests/test_egress_linux.py) in a
# privileged container.
#
# When to use: on a Windows or macOS dev host, where the suite skips these
# tests (no nftables, no network namespaces). On a Linux host run them
# directly instead:  sudo .venv/bin/python -m pytest tests/test_egress_linux.py
#
# Why a privileged container: the tests create network namespaces and load
# nftables rules, which needs CAP_NET_ADMIN and CAP_SYS_ADMIN. Everything
# happens inside the container's own network namespace; the host is untouched.
#
# Usage: scripts/test-egress-linux.sh [pytest args...]
#   scripts/test-egress-linux.sh            # all of them, quiet
#   scripts/test-egress-linux.sh -v -k uid  # verbose, the per-uid tests only
#
# Needs a running Docker daemon. The repo is mounted read-only.
set -euo pipefail

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
    exit 0
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${AL_TEST_IMAGE:-python:3.12-slim}"

if ! docker info >/dev/null 2>&1; then
    echo "error: no Docker daemon reachable (start Docker, then retry)" >&2
    exit 1
fi

# Git Bash on Windows rewrites /paths in arguments; switch that off.
export MSYS_NO_PATHCONV=1

# The environment is built inside the container (the checkout's own .venv
# belongs to the host OS and the mount is read-only).
docker run --rm --privileged -v "$ROOT:/src:ro" \
    -e UV_PROJECT_ENVIRONMENT=/venv -e UV_LINK_MODE=copy -e PYTHONDONTWRITEBYTECODE=1 \
    "$IMAGE" sh -c '
    set -e
    log=/tmp/setup.log
    {
        apt-get update && apt-get install -y --no-install-recommends nftables iproute2 util-linux
        pip install --root-user-action=ignore uv
        cd /src && uv sync --frozen
    } >"$log" 2>&1 || { echo "error: container setup failed:" >&2; tail -n 40 "$log" >&2; exit 1; }
    cd /src
    exec /venv/bin/python -m pytest tests/test_egress_linux.py -p no:cacheprovider -rs "$@"
' sh "${@:--q}"
