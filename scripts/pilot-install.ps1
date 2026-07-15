# One-command pilot install (Windows): workspace -> keys -> suite ->
# release gate -> sealed Docker topology, verified end to end.
#
#   powershell -ExecutionPolicy Bypass -File scripts/pilot-install.ps1
#
# Linux/macOS: scripts/pilot-install.sh (same flow).
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

function Need($cmd, $hint) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Error "error: '$cmd' is required - $hint"
    }
}
Need uv "https://docs.astral.sh/uv/"
Need docker "https://docs.docker.com/desktop/"

Write-Host "[1/6] install the workspace (uv sync)"
uv sync
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "[2/6] initialize keys + workspace"
uv run al init --config configs/balanced.yaml
if ($LASTEXITCODE -ne 0) { exit 1 }
if (-not (Test-Path keys/admin_api_token)) {
    uv run python -c "import secrets,sys;sys.stdout.write(secrets.token_urlsafe(32))" | Set-Content -NoNewline keys/admin_api_token
    Write-Host "wrote keys/admin_api_token"
}

Write-Host "[3/6] test suite"
uv run pytest -q
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "[4/6] release gate (tool-response injection blocked on all 3 MCP transports)"
uv run python examples/tool-response-injection/demo.py
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "[5/6] sealed topology (docker compose up)"
docker compose up -d --build
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "[6/6] verify the topology proofs"
foreach ($svc in @("agent-selftest", "agent-control-probe")) {
    $cid = docker compose ps -aq $svc
    for ($i = 0; $i -lt 60; $i++) {
        $state = docker inspect -f '{{.State.Status}}' $cid
        if ($state -eq "exited") { break }
        Start-Sleep -Seconds 2
    }
    $code = docker inspect -f '{{.State.ExitCode}}' $cid
    if ($code -ne "0") {
        Write-Error "FAIL: $svc exited $code - the topology did not prove itself; do not run agents on it"
    }
    Write-Host "  ${svc}: proof held (exit 0)"
}

$health = uv run python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8443/healthz',timeout=10).status)"
if ($health -ne "200") { Write-Error "FAIL: data plane /healthz returned $health" }
Write-Host "  data plane: healthy (chain verified at boot)"

Write-Host ""
Write-Host "pilot install complete."
Write-Host "  data plane   http://127.0.0.1:8443   (fetch + LLM reverse proxy + POST /mcp)"
Write-Host "  control      http://127.0.0.1:8898   (kill switch + dashboard; token: keys/admin_api_token)"
Write-Host "next steps:"
Write-Host "  docker compose exec al-core al vkey issue <user> --max-requests 500"
Write-Host "  docker compose exec al-core al identity issue <org> <agent>"
Write-Host "  deployment guides: deployment/README.md   rollout modes: docs/rollout.md"
