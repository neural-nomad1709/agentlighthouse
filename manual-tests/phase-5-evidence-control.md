# Phase 5 manual tests — Evidence & Control (MCP transports, kill switch, SIEM)

What you verify: the release-gate demo (tool-response injection blocked on
all three MCP transports), the kill switch from all sources, SIEM export
with verifiable alerts, and (Part B) live control/data plane segregation.

## Environment setup

1. Complete the [common setup](README.md#common-environment-setup).
2. Part A runs natively. Part B needs Docker.
3. For Part B, the compose stack reads two secret files from `keys/`. Confirm
   they exist; create the admin token if missing:

   - Windows (PowerShell):

     ```powershell
     if (-not (Test-Path keys/admin_api_token)) { python -c "import secrets;print(secrets.token_urlsafe(32),end='')" | Set-Content -NoNewline keys/admin_api_token }
     ```

   - Linux/macOS (bash):

     ```bash
     [ -f keys/admin_api_token ] || python -c "import secrets;print(secrets.token_urlsafe(32),end='')" > keys/admin_api_token
     ```

## Test data preparation

None — the release-gate demo ships its own hostile MCP server
(`examples/tool-response-injection/mock_server.py`): clean name, clean
description, with the injection payload hidden in the tool's RESPONSE, so
descriptor pinning and poison scans pass and the response scan must catch it.

## Tests (Part A — native)

### 5.1 The release gate

```
make demo
```

(Equivalent without make: `uv run python examples/tool-response-injection/demo.py`.)

Expected transcript, ending `RELEASE GATE PASSED`, exit 0:

- [1] stdio transport (real subprocess) -> `INJECTION_BLOCKED`, exfil payload withheld
- [2] HTTP upstream -> `INJECTION_BLOCKED`, exfil payload withheld
- [3] HTTP reverse (`POST /mcp`) -> `INJECTION_BLOCKED`, exfil payload withheld
- [4] kill switch -> even an allowed tool denied; disengage resumes
- [5] evidence -> receipts with no exfil payload in the ledger; SIEM alert
  tagged `T1204`/`ASI01`; al-verify passes in a subprocess where importing
  `al_core` is forced to fail (the portability proof)

If this fails, stop: the release gate failing means no release.

### 5.2 Kill switch engages, reports, and disengages (CLI source)

```
uv run al killswitch engage --reason "manual drill"
uv run al killswitch status
uv run al killswitch disengage
uv run al killswitch status
```

Expected: after engage, `status` reports engaged with exit 3 (scriptable);
after disengage, exit 0. Engage/disengage are receipted (engage = CRITICAL);
check with `uv run al export --verdict block` — the engagement appears as a
MITRE-tagged alert.

### 5.3 The sentinel file IS the state (crash-safe, out-of-band source)

1. Engage by touching the sentinel directly (what an incident script or
   SIGUSR1 handler does):

   - Windows: `New-Item -ItemType File data/killswitch/ENGAGED -Force | Out-Null`
   - Linux: `mkdir -p data/killswitch && touch data/killswitch/ENGAGED`

2. `uv run al killswitch status` — expected: engaged, exit 3, no daemon
   involved.
3. `uv run al killswitch disengage` — expected: sentinel removed, exit 0.

### 5.4 SIEM export is verifiable evidence, not just logs

```
uv run al export --verdict block -o data/alerts.ndjson
```

Open `data/alerts.ndjson`: each line is an ECS-shaped event where blocks are
`event.kind: alert`, MITRE technique ids ride `threat.technique.id`, OWASP
ASI tags ride `al.owasp`, and every event carries `record_hash` + `sig` — an
analyst can pull the receipt by hash and verify it with `al-verify` alone.

## Tests (Part B — Docker segregation drill)

### 5.5 Both probes gate the agent on every up

```
docker compose up -d --build
docker compose logs agent-selftest agent-control-probe
```

Expected: BOTH one-shot probes exit 0 — `agent-selftest` proves no
out-of-band egress; `agent-control-probe` proves NO ROUTE from agent-net to
the control plane (al-control:8888/8898). `agent-sandbox` starts only after
both proofs.

### 5.6 Agents cannot even resolve the control plane

```
docker compose exec agent-sandbox wget -T 5 -O- http://al-control:8888/api/killswitch
```

Expected: `bad address` — the name does not resolve from agent-net.

### 5.7 Operator engages via the control plane; the data plane obeys

The two planes share NO network path — the kill switch crosses as a sentinel
file on a shared volume. `<TOKEN>` is the content of `keys/admin_api_token`
(Windows: `Get-Content keys/admin_api_token`; Linux: `cat keys/admin_api_token`).

```
curl.exe -X POST http://127.0.0.1:8898/api/killswitch -H "Authorization: Bearer <TOKEN>" -d "{\"reason\":\"live drill\"}"
curl.exe -i "http://127.0.0.1:8443/fetch?url=https://example.com"
curl.exe -i -X POST http://127.0.0.1:8443/v1/messages -d "{}"
curl.exe -i http://127.0.0.1:8443/healthz
```

Expected: the engage returns `{"engaged":true,...}`; fetch and the reverse
proxy answer `503` with `X-AL-Block-Reason: KILLSWITCH_ENGAGED`; `/healthz`
stays `200` (operators need health during an incident). From inside the
sandbox, any proxied request also gets 503.

### 5.8 Disengage resumes traffic

```
curl.exe -X POST http://127.0.0.1:8898/api/killswitch -H "Authorization: Bearer <TOKEN>" -d "{\"engage\":false}"
curl.exe -i "http://127.0.0.1:8443/fetch?url=https://example.com"
```

Expected: the fetch now fails with `401 NO_IDENTITY` — normal policy is back
in charge (401, not 503, is the proof).

### 5.9 Each plane's evidence verifies independently

```
docker compose exec al-core al-verify /app/data/ledger.jsonl --pubkey /app/data/keys/mediator_ed25519.pub
docker compose exec al-control al-verify /app/data/ledger.jsonl --pubkey /app/data/keys/mediator_ed25519.pub
```

Expected: both chains verify OK — one writer per plane, by construction.

## Cleanup

```
docker compose down -v
Remove-Item data/alerts.ndjson            # Linux: rm data/alerts.ndjson
```
