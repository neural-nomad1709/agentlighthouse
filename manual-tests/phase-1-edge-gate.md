# Phase 1 manual tests — Edge Gate (L0 egress + L1 proxies)

What you verify: identity-gated fetch/CONNECT/reverse proxies, host/port
default-deny, SSRF blocking that no allowlist can override, virtual keys, the
L0 bypass self-test, and (Part B) the sealed Docker topology.

Part A runs natively on Windows or Linux. Part B needs Docker.

## Environment setup

1. Complete the [common setup](README.md#common-environment-setup).
2. These tests make outbound requests to `example.com` — the machine needs
   internet access.
3. You will run the gateway in one terminal and issue requests from a second.

## Test data preparation

1. Create a test config that allowlists `example.com` and — deliberately —
   two SSRF targets, to prove the allowlist cannot override an SSRF block:

   ```
   Copy-Item configs/balanced.yaml configs/_manual_p1.yaml     # Linux: cp
   ```

   Edit `configs/_manual_p1.yaml` and change the `gateway.allow_hosts` line to:

   ```yaml
   allow_hosts: [example.com, "169.254.169.254", "10.0.0.8"]
   ```

2. Issue an agent identity (the bearer token is shown once — copy it):

   ```
   uv run al identity issue acme tester
   ```

   Note the SPIFFE id (`spiffe://acme/agent/tester`) and the token. Below,
   `<TOKEN>` means this value.

3. Issue a virtual LLM key for the reverse-proxy tests (shown once — copy it;
   `<ALK>` below):

   ```
   uv run al vkey issue alice --org acme --max-requests 5
   ```

4. Start the gateway in terminal 1 and leave it running:

   ```
   uv run al gateway --host 127.0.0.1 --config configs/_manual_p1.yaml
   ```

   The fetch/reverse proxy listens on `127.0.0.1:8443`; the CONNECT forward
   proxy on `127.0.0.1:8080`.

## Tests (Part A — native)

Run these from terminal 2. On Windows use `curl.exe`.

### 1.1 No identity, no egress

```
curl.exe -i "http://127.0.0.1:8443/fetch?url=https://example.com/"
```

Expected: `401` with header `X-AL-Block-Reason: NO_IDENTITY`.

### 1.2 Identity + allowlisted host passes

```
curl.exe -i "http://127.0.0.1:8443/fetch?url=https://example.com/" -H "X-AL-Identity: spiffe://acme/agent/tester" -H "Authorization: Bearer <TOKEN>"
```

Expected: `200` and the example.com HTML body.

### 1.3 Default-deny: a host not on the allowlist is refused

Same command with `url=https://www.wikipedia.org/`.

Expected: `403`, `X-AL-Block-Reason: HOST_NOT_ALLOWED`.

### 1.4 SSRF beats the allowlist

Both targets ARE on this config's allowlist — and are still blocked:

```
curl.exe -i "http://127.0.0.1:8443/fetch?url=http://169.254.169.254/latest/meta-data/" -H "X-AL-Identity: spiffe://acme/agent/tester" -H "Authorization: Bearer <TOKEN>"
curl.exe -i "http://127.0.0.1:8443/fetch?url=http://10.0.0.8/admin" -H "X-AL-Identity: spiffe://acme/agent/tester" -H "Authorization: Bearer <TOKEN>"
```

Expected: both `403`, `X-AL-Block-Reason: SSRF_BLOCKED` (cloud metadata
endpoint; RFC 1918 address). An operator allowlist can never re-open SSRF.

### 1.5 Port allowlist

Same command with `url=https://example.com:8444/`.

Expected: `403`, `X-AL-Block-Reason: PORT_NOT_ALLOWED` (only 80/443 allowed).

### 1.6 CONNECT forward proxy requires proxy identity

```
curl.exe -i -x http://127.0.0.1:8080 https://example.com/
curl.exe -i -x http://127.0.0.1:8080 --proxy-user "spiffe://acme/agent/tester:<TOKEN>" https://example.com/
```

Expected: first command fails with `407` (proxy authentication required —
NO_IDENTITY). Second establishes the tunnel and returns `200` (the SPIFFE id
contains colons; the proxy splits credentials on the last colon, so plain
`--proxy-user` works).

### 1.7 Reverse proxy: virtual keys gate LLM traffic

```
curl.exe -i -X POST http://127.0.0.1:8443/v1/messages -H "Content-Type: application/json" -d "{\"model\":\"claude-sonnet-5\",\"max_tokens\":16,\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}"
curl.exe -i -X POST http://127.0.0.1:8443/v1/messages -H "Authorization: Bearer <ALK>" -H "Content-Type: application/json" -d "{\"model\":\"claude-sonnet-5\",\"max_tokens\":16,\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}"
```

Expected: first `401 INVALID_VIRTUAL_KEY`. Second `502
UPSTREAM_NOT_CONFIGURED` — the key authenticated and the content gate passed;
only the provider key is missing. (Optional live test: set
`AL_GATEWAY__UPSTREAM__ANTHROPIC_API_KEY`, restart the gateway, and the same
call returns a real completion; the sixth call in a day exceeds the
`--max-requests 5` budget with `429 BUDGET_EXCEEDED`.)

### 1.8 Key hygiene

```
uv run al vkey list
```

Expected: the key is listed by user/org/budget with a hash — never the
`alk_` plaintext, which was shown exactly once at issue time.

### 1.9 L0 bypass self-test (negative on an open host)

```
uv run al egress selftest
```

Expected on a normal workstation: exit code 1, reporting that out-of-band
egress was found — this host is NOT a sealed agent network, and the probe
proves it can tell. (Exit 0 means the choke-point holds; you will see that
from inside the sealed container network in Part B.)

### 1.10 nftables ruleset renders

```
uv run al egress nftables
```

Expected: the agent-netns default-deny nftables ruleset prints (render only;
`--apply` is for a Linux agent host).

### 1.11 Evidence check

Stop the gateway (Ctrl+C in terminal 1), then:

```
uv run al db stats
uv run al-verify data/ledger.jsonl --pubkey keys/mediator_ed25519.pub
```

Expected: `fetch` receipts covering the allows and blocks above, with the
block reasons you observed; the chain verifies `OK`.

## Tests (Part B — Docker topology)

Requires Docker Desktop (Windows) or Docker Engine + compose (Linux), running.

### 1.12 The topology proves itself on every `up`

```
docker compose up -d --build
docker compose ps
docker compose logs agent-selftest
```

Expected: `al-core` reaches `healthy`; `agent-selftest` exited with code 0
logging `egress choke-point holds (2 probes denied)`; `agent-sandbox` started
only after that proof.

### 1.13 The agent network is sealed

```
docker compose exec agent-sandbox wget -T 5 -O- http://1.1.1.1
```

Expected: `Network unreachable` — agent-net is `internal: true`; the only
road out is al-core.

### 1.14 The proxy is reachable but demands identity

```
docker compose exec agent-sandbox wget -T 5 -O- https://example.com/
```

Expected: failure citing HTTP `407` — the sandbox's `HTTPS_PROXY` points at
al-core:8080, which refuses an unidentified tunnel (NO_IDENTITY).

### 1.15 Data plane healthy from the host

```
curl.exe http://127.0.0.1:8443/healthz
```

Expected: `healthy` with the receipt chain verified.

## Cleanup

```
docker compose down -v
Remove-Item configs/_manual_p1.yaml       # Linux: rm configs/_manual_p1.yaml
```
