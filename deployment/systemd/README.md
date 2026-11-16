# Deployment: native Linux (systemd), agent and mediator on one host

**Profile:** one Linux host, no containers. The mediator runs as a systemd
service under its own account. Agents run under a second account, and the
kernel confines that account: it can reach the mediator's two ports on
loopback and nothing else. The mediator does not start until that has been
proven.

Use this when agents must run directly on a host. When you can run
containers, prefer the compose topology in [../mid-size/](../mid-size/README.md):
it also separates the control plane and gives each plane its own filesystem.

## What enforces what

| Piece | Does |
|-------|------|
| `al-egress.service` (root, one-shot) | Loads an nftables table that matches the agent account's uid: loopback TCP to ports 8080 and 8443 is accepted, everything else that account sends is dropped (DNS and IPv6 included). Then runs `al egress selftest` **as the agent account**. If a direct connection to the internet succeeds, the unit fails. |
| `al-core.service` (account `al-core`) | The gateway on `127.0.0.1:8443` and the CONNECT forward proxy on `127.0.0.1:8080`. `Requires=al-egress.service`: no proof, no mediator. Runs with no capabilities, a read-only view of the system, and the container baseline's limits (256 tasks, 1G memory). |
| Account `al-agent` | Whatever you run as this account is confined. Other accounts are not touched, the mediator's included. |

## Install

Needs: systemd, Python 3.12+, `nftables`, `util-linux` (`setpriv`), and a
version of AgentLighthouse whose `al egress nftables --help` lists
`--agent-uid`. Run as root.

1. Accounts:

   ```bash
   useradd --system --no-create-home --shell /usr/sbin/nologin al-core
   useradd --system --no-create-home --shell /usr/sbin/nologin al-agent
   ```

   Give `al-agent` no sudo rights and no membership in privileged groups.

2. The software, in a location both accounts can read and neither can write:

   ```bash
   python3 -m venv /opt/agentlighthouse/venv
   /opt/agentlighthouse/venv/bin/pip install agentlighthouse-core
   ```

3. Config, policy and the signing key:

   ```bash
   install -d -m 0755 /etc/agentlighthouse
   cd /etc/agentlighthouse
   /opt/agentlighthouse/venv/bin/al init     # writes configs/, policies/, keys/, .env, data/
   rm -rf .env data                          # dev conveniences; this install does not use them
   chown -R al-core:al-core keys
   chmod 0700 keys
   chmod 0400 keys/mediator_ed25519
   ```

   Then edit `configs/balanced.yaml` (`gateway.allow_hosts`: the hosts agents
   may reach; empty means none) and `policies/default-deny.yaml` (per-identity
   tool rules). Leave `env: dev` as shipped: `env: prod` arms a self-test
   inside the mediator, which has egress by design and would refuse to start.
   The proof for this install is the one `al-egress.service` runs.

   Provider keys, if you use the reverse proxy, go in
   `/etc/agentlighthouse/al-core.env` (root-owned, mode 0600):
   `AL_GATEWAY__UPSTREAM__ANTHROPIC_API_KEY=...`,
   `AL_GATEWAY__UPSTREAM__OPENAI_API_KEY=...`.

4. Units:

   ```bash
   cp al-egress.service al-core.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now al-core.service      # pulls in al-egress.service
   ```

5. Demand the proof:

   ```bash
   systemctl is-active al-egress.service al-core.service    # active, active
   journalctl -u al-egress.service -n 5                     # "egress choke-point holds"
   nft list table inet al_egress_agent
   ```

6. Issue an identity and run the agent as `al-agent`, pointed at the proxy:

   ```bash
   cd /etc/agentlighthouse
   setpriv --reuid=al-core --regid=al-core --init-groups \
       /opt/agentlighthouse/venv/bin/al identity issue acme my-agent --data-dir /var/lib/agentlighthouse
   ```

   The agent uses `HTTPS_PROXY=http://127.0.0.1:8080` with its identity
   credentials, and LLM SDKs point at `http://127.0.0.1:8443/v1`. It cannot
   resolve names itself; the proxy does that.

Evidence lives in `/var/lib/agentlighthouse` (owned by `al-core`, mode 0700).
Verify it at any time:

```bash
/opt/agentlighthouse/venv/bin/al-verify /var/lib/agentlighthouse/ledger.jsonl \
    --pubkey /var/lib/agentlighthouse/mediator_ed25519.pub
```

## Changing the ports or the account names

The ports appear in three places that must agree: `--port` in
`al-core.service` (gateway), `gateway.forward_listen` in the config (forward
proxy), and the two `--port` flags in `al-egress.service`. Never add the
control plane's port to `al-egress.service`: the agent account must not reach
it.

## What this does and does not give you

- **The confinement follows the uid.** A process that changes uid leaves it.
  That is why `al-agent` must have no sudo rights. Setuid programs on the
  host run as their owner and are not confined.
- **It is network confinement only.** Both accounts share one filesystem and
  one kernel. The agent cannot read the evidence or the signing key (file
  modes), but there is no sandbox around it.
- **root can unload the table.** So can anything with `CAP_NET_ADMIN`.
- **The boot receipt still records `egress.advisory_mode`.** The mediator
  does not measure the confinement itself; the proof is in the journal of
  `al-egress.service`, not in the signed ledger.
- **The proof is as good as the host's own connectivity.** The self-test
  passes when the agent account cannot connect to `1.1.1.1:443` and
  `8.8.8.8:53`. On a host that cannot reach those anyway it proves nothing;
  point `--target` at something the host can reach.
- **The control plane (dashboard, admin API) has no unit here.** The kill
  switch still works from the host: `al killswitch`, the sentinel file, or
  `SIGUSR1` to the service.
- **Tested in a container, not on bare metal.** `scripts/test-systemd-units.sh`
  installs exactly these steps under systemd 255 on Ubuntu 24.04 and checks
  each property above. No run on a physical host or a cloud VM has been done.
