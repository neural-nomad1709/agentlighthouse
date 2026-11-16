#!/usr/bin/env bash
# Install the native Linux deployment (deployment/systemd/) into a throwaway
# container that boots systemd, then check that it enforces what the guide
# says it enforces.
#
# When to use: after changing deployment/systemd/*.service, the per-uid
# nftables ruleset, or `al egress`. It is the only check that runs the units
# under a real systemd; the test suite only reads them as text.
#
# What it checks:
#   - al-egress.service and al-core.service start; /healthz answers
#   - the agent account reaches the mediator's ports and nothing else
#   - other accounts keep their egress
#   - with the ruleset missing, al-egress fails and al-core does not start
#
# Usage: scripts/test-systemd-units.sh [--keep]
#   --keep   leave the container running for inspection
#            (docker exec -it al-systemd-check bash)
#
# Needs a running Docker daemon with outbound network access. The container
# is privileged (systemd, nftables); the repo is mounted read-only. Setup
# output goes to a log inside the container and is shown only on failure.
set -euo pipefail

KEEP=0
case "${1:-}" in
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    --keep) KEEP=1 ;;
    "") ;;
    *) echo "error: unknown argument: $1 (try --help)" >&2; exit 2 ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME=al-systemd-check
IMAGE=al-systemd-check:local

docker info >/dev/null 2>&1 || { echo "error: no Docker daemon reachable" >&2; exit 1; }
export MSYS_NO_PATHCONV=1

echo "building the systemd image (quiet)..."
docker build -q -t "$IMAGE" - >/dev/null <<'DOCKERFILE'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd systemd-sysv python3 python3-venv nftables iproute2 util-linux ca-certificates \
    && rm -rf /var/lib/apt/lists/*
CMD ["/sbin/init"]
DOCKERFILE

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --privileged --cgroupns=host \
    --tmpfs /run --tmpfs /run/lock -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$ROOT:/src:ro" "$IMAGE" >/dev/null
cleanup() { [ "$KEEP" = 1 ] || docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker exec -i "$NAME" bash -s <<'INSIDE'
set -uo pipefail
LOG=/var/log/al-install.log
AL=/opt/agentlighthouse/venv/bin/al
PY=/opt/agentlighthouse/venv/bin/python
failures=0

ok()   { echo "  ok    $*"; }
fail() { echo "  FAIL  $*"; failures=$((failures + 1)); }
# check "<description>" <expected exit: 0|nonzero> <command...>
check() {
    local what=$1 want=$2; shift 2
    if "$@" >>"$LOG" 2>&1; then got=0; else got=nonzero; fi
    if [ "$got" = "$want" ]; then ok "$what"; else fail "$what"; fi
}
as_agent() { setpriv --reuid=al-agent --regid=al-agent --init-groups "$@"; }
connects() { "$PY" -c "import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3)" "$1" "$2"; }
healthz()  { "$PY" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8443/healthz', timeout=5)"; }

for _ in $(seq 30); do systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && break; sleep 1; done

echo "installing (log: $LOG in the container)..."
{
    set -e
    # The steps of deployment/systemd/README.md. The one difference: the
    # package comes from this checkout, not from PyPI.
    useradd --system --no-create-home --shell /usr/sbin/nologin al-core
    useradd --system --no-create-home --shell /usr/sbin/nologin al-agent
    python3 -m venv /opt/agentlighthouse/venv
    /opt/agentlighthouse/venv/bin/pip install uv
    (cd /src && UV_PROJECT_ENVIRONMENT=/opt/agentlighthouse/venv UV_LINK_MODE=copy \
        /opt/agentlighthouse/venv/bin/uv sync --frozen --no-dev)
    install -d -m 0755 /etc/agentlighthouse
    (cd /etc/agentlighthouse && "$AL" init && rm -rf .env data)
    chown -R al-core:al-core /etc/agentlighthouse/keys
    chmod 0700 /etc/agentlighthouse/keys
    chmod 0400 /etc/agentlighthouse/keys/mediator_ed25519
    cp /src/deployment/systemd/al-egress.service /src/deployment/systemd/al-core.service /etc/systemd/system/
    systemctl daemon-reload
    set +e
} >"$LOG" 2>&1 || { echo "error: install failed:" >&2; tail -n 40 "$LOG" >&2; exit 1; }

echo "units"
check "al-core.service starts (pulls in al-egress.service)" 0 systemctl start al-core.service
check "al-egress.service is active" 0 systemctl is-active al-egress.service
sleep 3
check "al-core.service is still active" 0 systemctl is-active al-core.service
check "al-core runs as the al-core account" 0 \
    sh -c '[ "$(ps -o user= -p "$(systemctl show -p MainPID --value al-core.service)")" = al-core ]'
check "the service sees its own key directory read-only" 0 \
    sh -c 'nsenter -t "$(systemctl show -p MainPID --value al-core.service)" -m \
        setpriv --reuid=al-core --regid=al-core --init-groups \
        touch /etc/agentlighthouse/keys/probe 2>&1 | grep -q "Read-only file system"'

echo "mediator"
check "/healthz answers" 0 healthz
check "the mediator's own egress works (control for the checks below)" 0 connects 1.1.1.1 443

echo "agent account"
"$PY" -m http.server 9999 --bind 127.0.0.1 >/dev/null 2>&1 &
sleep 1
check "reaches the gateway (8443)" 0 as_agent "$PY" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8443/healthz', timeout=5)"
check "reaches the forward proxy (8080)" 0 as_agent "$PY" -c "import socket; socket.create_connection(('127.0.0.1', 8080), timeout=3)"
check "cannot reach the internet directly" nonzero as_agent "$PY" -c "import socket; socket.create_connection(('1.1.1.1', 443), timeout=3)"
check "cannot reach another local service (9999)" nonzero as_agent "$PY" -c "import socket; socket.create_connection(('127.0.0.1', 9999), timeout=3)"
check "that local service is reachable by other accounts" 0 connects 127.0.0.1 9999
check "cannot read the evidence directory" nonzero as_agent ls /var/lib/agentlighthouse
check "cannot read the signing key" nonzero as_agent cat /etc/agentlighthouse/keys/mediator_ed25519

echo "operator commands from the guide"
check "al identity issue works as the al-core account" 0     sh -c 'cd /etc/agentlighthouse && setpriv --reuid=al-core --regid=al-core --init-groups         "$0" identity issue acme my-agent --data-dir /var/lib/agentlighthouse' "$AL"
check "al-verify verifies the ledger" 0     /opt/agentlighthouse/venv/bin/al-verify /var/lib/agentlighthouse/ledger.jsonl     --pubkey /var/lib/agentlighthouse/mediator_ed25519.pub
check "the boot receipt records advisory mode" 0     grep -q egress.advisory_mode /var/lib/agentlighthouse/ledger.jsonl

echo "restart"
check "al-egress.service restarts cleanly" 0 systemctl restart al-egress.service
check "the ruleset holds one copy after the restart" 0 \
    sh -c '[ "$(nft list table inet al_egress_agent | grep -c skuid)" = 2 ]'

echo "proof gate (ruleset removed, apply step disabled)"
systemctl stop al-core.service al-egress.service >>"$LOG" 2>&1
nft delete table inet al_egress_agent >>"$LOG" 2>&1
mkdir -p /etc/systemd/system/al-egress.service.d
selftest_line=$(grep '^ExecStart=/usr/bin/setpriv' /etc/systemd/system/al-egress.service)
printf '[Service]\nExecStart=\n%s\n' "$selftest_line" > /etc/systemd/system/al-egress.service.d/no-apply.conf
systemctl daemon-reload
check "al-egress.service fails when the agent can reach the internet" nonzero systemctl start al-egress.service
check "al-core.service does not start without the proof" nonzero systemctl start al-core.service
check "al-core.service is not active" nonzero systemctl is-active al-core.service

echo
if [ "$failures" -gt 0 ]; then
    echo "$failures check(s) FAILED. Last log lines:"; tail -n 30 "$LOG"
    echo "--- journal: al-core / al-egress ---"
    journalctl -u al-core.service -u al-egress.service --no-pager -n 30
    exit 1
fi
echo "all checks passed"
INSIDE
