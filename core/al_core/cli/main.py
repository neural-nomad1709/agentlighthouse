"""``al`` command-line entry point (Phases 0–4).

Commands: init, keygen, check, scan, db (init/stats), dashboard,
policy (check/show), mcp (review),
memory (put/get/list/snapshot/rollback/verify/quarantine), identity
(issue/list), vkey (issue/list/revoke), egress (selftest/nftables), gateway,
verify-receipt, healthz, run, version. More gates (killswitch, diagnose)
arrive in later phases.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path

import typer

from .. import __version__
from ..config import load_settings
from ..identity import IdentityRegistry
from ..keys import generate_signing_key, load_or_create_signing_key, public_key_hex

app = typer.Typer(
    name="al",
    help="AgentLighthouse — runtime security & governance plane for AI agents.",
    no_args_is_help=True,
    add_completion=False,
)
identity_app = typer.Typer(help="Manage SPIFFE-style agent identities.")
app.add_typer(identity_app, name="identity")
vkey_app = typer.Typer(help="Manage per-user virtual LLM keys + budgets.")
app.add_typer(vkey_app, name="vkey")
egress_app = typer.Typer(help="L0 egress enforcement: bypass self-test, nftables.")
app.add_typer(egress_app, name="egress")
db_app = typer.Typer(help="SQLite mirror: initialize + query the evidence store.")
app.add_typer(db_app, name="db")
policy_app = typer.Typer(help="L4 identity-bound tool policy: inspect + check.")
app.add_typer(policy_app, name="policy")
mcp_app = typer.Typer(help="MCP mediation: review advertised tools (pin + poison).")
app.add_typer(mcp_app, name="mcp")
memory_app = typer.Typer(help="L5 memory guard: guarded reads/writes, snapshot + rollback.")
app.add_typer(memory_app, name="memory")
killswitch_app = typer.Typer(help="L6 kill switch: engage/disengage full deny-all.")
app.add_typer(killswitch_app, name="killswitch")
learn_app = typer.Typer(help="Learning loop: mine rules, approve + sign, generate tests.")
app.add_typer(learn_app, name="learn")
skill_app = typer.Typer(help="Skill guard: screen + pin agent instruction files.")
app.add_typer(skill_app, name="skill")

DEFAULT_KEY = Path("keys/mediator_ed25519")
DEFAULT_DATA = Path("data")


def _err(msg: str) -> "typer.Exit":
    typer.secho(f"error: {msg}", fg=typer.colors.RED, err=True)
    return typer.Exit(1)


@app.command()
def version() -> None:
    """Print the al-core version."""
    typer.echo(f"al-core {__version__}")


@app.command()
def init(
    config: Path = typer.Option(None, "--config", "-c", help="config YAML to validate"),
) -> None:
    """Initialize a dev workspace: keys/, data/, .env, and a signing key."""
    Path("keys").mkdir(exist_ok=True)
    DEFAULT_DATA.mkdir(exist_ok=True)

    env_file = Path(".env")
    if not env_file.exists():
        token = secrets.token_urlsafe(32)
        env_file.write_text(
            "# AgentLighthouse dev settings (gitignored). NON-SECRET pointers + dev token only.\n"
            "AL_ENV=dev\n"
            "AL_MODE=balanced\n"
            f"AL_ADMIN_API_TOKEN={token}\n",
            encoding="utf-8",
        )
        typer.secho("wrote .env (dev)", fg=typer.colors.GREEN)
    else:
        typer.echo(".env already exists — leaving it")

    if not DEFAULT_KEY.exists():
        key = generate_signing_key(DEFAULT_KEY)
        typer.secho(f"generated signing key {DEFAULT_KEY} (0600)", fg=typer.colors.GREEN)
        typer.echo(f"public key: {public_key_hex(key.public_key())}")
    else:
        typer.echo(f"signing key {DEFAULT_KEY} already exists — leaving it")

    # Validate config if one was provided so init doubles as a smoke check.
    try:
        settings = load_settings(config)
        typer.secho(f"config OK — mode={settings.mode} env={settings.env}", fg=typer.colors.GREEN)
    except Exception as exc:  # noqa: BLE001
        raise _err(f"config invalid: {exc}")

    typer.echo("ready. try:  al healthz")


@app.command()
def keygen(
    path: Path = typer.Option(DEFAULT_KEY, "--path", help="signing key path"),
    force: bool = typer.Option(False, "--force", help="overwrite an existing key"),
) -> None:
    """Generate (or rotate with --force) the mediator Ed25519 signing key."""
    if path.exists() and not force:
        raise _err(f"{path} exists; pass --force to rotate (invalidates prior chain trust)")
    key = generate_signing_key(path)
    typer.secho(f"wrote {path} + {path}.pub", fg=typer.colors.GREEN)
    typer.echo(public_key_hex(key.public_key()))


@app.command()
def check(
    config: Path = typer.Option(None, "--config", "-c", help="config YAML to validate"),
) -> None:
    """Validate configuration (fail-closed: exits non-zero on any error)."""
    try:
        settings = load_settings(config)
    except Exception as exc:  # noqa: BLE001
        raise _err(f"config invalid: {exc}")
    typer.secho(
        f"config OK — mode={settings.mode} env={settings.env} listen={settings.listen}",
        fg=typer.colors.GREEN,
    )


@identity_app.command("issue")
def identity_issue(
    org: str = typer.Argument(..., help="organization label"),
    name: str = typer.Argument(..., help="agent name"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir", help="registry location"),
) -> None:
    """Issue a new agent identity + per-agent key + bearer token (shown once)."""
    registry = IdentityRegistry(data_dir / "identities.json")
    try:
        creds = registry.issue(org, name)
    except Exception as exc:  # noqa: BLE001
        raise _err(str(exc))
    typer.secho(f"issued {creds.identity.spiffe_id}", fg=typer.colors.GREEN)
    typer.echo(f"public_key: {creds.identity.public_key_hex}")
    typer.secho("bearer token (store now — not recoverable):", fg=typer.colors.YELLOW)
    typer.echo(creds.token)


@identity_app.command("list")
def identity_list(
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir", help="registry location"),
) -> None:
    """List registered agent identities."""
    registry = IdentityRegistry(data_dir / "identities.json")
    idents = registry.list()
    if not idents:
        typer.echo("(no identities registered)")
        return
    for i in idents:
        typer.echo(f"{i.spiffe_id}\t{i.created_ts}")


@vkey_app.command("issue")
def vkey_issue(
    user: str = typer.Argument(..., help="user this key belongs to"),
    org: str = typer.Option(None, "--org", help="tenant this key bills + reports to"),
    max_requests: int = typer.Option(None, "--max-requests", help="daily request budget"),
    max_tokens: int = typer.Option(None, "--max-tokens", help="daily token budget"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir", help="store location"),
) -> None:
    """Issue a virtual LLM key (plaintext shown once — not recoverable).

    With --org the key's receipts are scoped to that tenant, so its own
    operators can see them; without it they land in the org-less system bucket."""
    from ..gateway.vkeys import VirtualKeyStore

    store = VirtualKeyStore(data_dir / "virtual_keys.json")
    vk, token = store.issue(
        user, org=org,
        max_requests_per_day=max_requests, max_tokens_per_day=max_tokens
    )
    typer.secho(f"issued {vk.key_id} for {vk.actor}", fg=typer.colors.GREEN)
    typer.echo(
        f"budgets: requests/day={vk.max_requests_per_day or 'unlimited'} "
        f"tokens/day={vk.max_tokens_per_day or 'unlimited'}"
    )
    typer.secho("virtual key (store now — not recoverable):", fg=typer.colors.YELLOW)
    typer.echo(token)


@vkey_app.command("list")
def vkey_list(
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir", help="store location"),
) -> None:
    """List virtual keys (never shows key material)."""
    from ..gateway.vkeys import VirtualKeyStore

    keys = VirtualKeyStore(data_dir / "virtual_keys.json").list()
    if not keys:
        typer.echo("(no virtual keys issued)")
        return
    for vk in keys:
        state = "revoked" if vk.disabled else "active"
        typer.echo(f"{vk.key_id}\t{vk.user}\t{state}\t{vk.created_ts}")


@vkey_app.command("revoke")
def vkey_revoke(
    key_id: str = typer.Argument(..., help="key id (vk_...)"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir", help="store location"),
) -> None:
    """Revoke a virtual key (immediate deny on next use)."""
    from ..gateway.vkeys import VirtualKeyStore

    if not VirtualKeyStore(data_dir / "virtual_keys.json").revoke(key_id):
        raise _err(f"no such key: {key_id}")
    typer.secho(f"revoked {key_id}", fg=typer.colors.GREEN)


@egress_app.command("selftest")
def egress_selftest(
    targets: list[str] = typer.Option(
        ["1.1.1.1:443", "8.8.8.8:53"], "--target", help="host:port probes (repeatable)"
    ),
    timeout: float = typer.Option(3.0, "--timeout", help="per-probe timeout seconds"),
) -> None:
    """Probe for out-of-band egress. Exit 0 = choke-point holds; 1 = bypass found.

    Run inside the agent netns/container (entrypoint precondition). A CONNECTED
    probe means the network is NOT default-deny — refuse to start the agent.
    """
    from ..egress import probe_bypass

    reached = probe_bypass(targets, timeout_s=timeout)
    if reached:
        typer.secho(
            f"CRITICAL: out-of-band egress succeeded to {', '.join(reached)} — "
            "this network is not a choke-point",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1)
    typer.secho(f"egress choke-point holds ({len(list(targets))} probes denied)", fg=typer.colors.GREEN)


@egress_app.command("nftables")
def egress_nftables(
    al_core_ip: str = typer.Option(..., "--al-core-ip", help="al-core address on agent-net"),
    ports: list[int] = typer.Option([8080, 8888], "--port", help="al-core proxy ports (repeatable)"),
    no_dns: bool = typer.Option(False, "--no-dns", help="drop DNS-to-al-core rules too"),
    apply: bool = typer.Option(False, "--apply", help="apply via `nft -f -` (Linux, NET_ADMIN)"),
) -> None:
    """Render (or apply) the agent-netns default-deny nftables ruleset."""
    import subprocess
    import sys

    from ..egress import render_ruleset

    rules = render_ruleset(
        al_core_ip=al_core_ip, proxy_ports=ports, allow_dns_to_al_core=not no_dns
    )
    if not apply:
        typer.echo(rules)
        return
    if sys.platform != "linux":
        raise _err("--apply requires Linux with NET_ADMIN (render-only elsewhere)")
    proc = subprocess.run(["nft", "-f", "-"], input=rules.encode(), capture_output=True)
    if proc.returncode != 0:
        raise _err(f"nft failed: {proc.stderr.decode(errors='replace').strip()}")
    typer.secho("nftables ruleset applied", fg=typer.colors.GREEN)


@db_app.command("init")
def db_init(
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir", help="db + ledger location"),
) -> None:
    """Create the SQLite mirror (schema: events, identities, quotas) if absent.

    The mirror is a *query surface* only — the JSONL ledger is canonical. Boot
    reconciles it from JSONL; this just materializes an empty, valid db so the
    dashboard has something to read before the first receipt."""
    from ..audit.db import SqliteMirror

    path = data_dir / "al.sqlite"
    path.parent.mkdir(parents=True, exist_ok=True)
    mirror = SqliteMirror(path)
    events = mirror.count_events()
    mirror.close()
    typer.secho(f"db ready at {path} ({events} events mirrored)", fg=typer.colors.GREEN)


@db_app.command("stats")
def db_stats(
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir", help="db location"),
) -> None:
    """Print evidence-store aggregates (events, verdicts, actions, actors)."""
    from ..audit.db import SqliteMirror

    path = data_dir / "al.sqlite"
    if not path.exists():
        raise _err(f"no db at {path} — run `al db init` or boot the runtime first")
    mirror = SqliteMirror(path)
    stats = mirror.stats()
    mirror.close()
    typer.echo(json.dumps(stats, indent=2))


@app.command()
def dashboard(
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    host: str = typer.Option("127.0.0.1", "--host", help="bind host (control-net only)"),
    port: int = typer.Option(8899, "--port", help="dashboard port"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
    dataplane_dir: Path = typer.Option(
        None, "--dataplane-dir",
        help="a running gateway's data dir, attached READ-ONLY so its receipts "
             "show here live (never point --data-dir at a running gateway's "
             "dir — two writers would race one chain). Replaces the whole "
             "'control' config section; prefer AL_CONTROL__DATAPLANE_DIR to "
             "combine with other control.* settings."),
    dataplane_pubkey: Path = typer.Option(
        None, "--dataplane-pubkey",
        help="public key that verifies the data plane's chain. Defaults to "
             "<dataplane-dir>/keys/mediator_ed25519.pub, which is where the "
             "container image keeps it — a native install keeps keys/ beside "
             "the repo, so pass it explicitly or the dashboard cannot verify "
             "that chain and reports it unverified."),
) -> None:
    """Serve the read-only evidence dashboard (control plane; admin-token gated).

    Boots the control-plane app (fail-closed) and serves the static dashboard
    at ``/dashboard`` plus the read-only ``/api/*`` evidence endpoints. Bind to
    control-net only — agents must never reach it."""
    import uvicorn

    from ..app import create_app

    overrides: dict = {}
    if dataplane_dir is not None:
        control: dict = {"dataplane_dir": str(dataplane_dir)}
        if dataplane_pubkey is not None:
            control["dataplane_pubkey"] = str(dataplane_pubkey)
        overrides["control"] = control
    elif dataplane_pubkey is not None:
        raise _err("--dataplane-pubkey needs --dataplane-dir (it verifies that "
                   "plane's chain)")
    try:
        application = create_app(config, data_dir=data_dir, **overrides)
    except Exception as exc:  # noqa: BLE001 — boot is fail-closed
        raise _err(f"refusing to start: {exc}")
    typer.secho(f"dashboard on http://{host}:{port}/dashboard", fg=typer.colors.GREEN)
    uvicorn.run(application, host=host, port=port)


@app.command()
def scan(
    text: str = typer.Argument(None, help="text to scan (or read stdin with --stdin)"),
    stdin: bool = typer.Option(False, "--stdin", help="read content from stdin"),
    file: Path = typer.Option(None, "--file", "-f", help="read content from a file"),
    config: Path = typer.Option(None, "--config", "-c", help="config YAML (mode + scanners)"),
    show_variants: bool = typer.Option(False, "--variants", help="print L2 normalization variants"),
) -> None:
    """Run the L2/L3 content gate over text and print the verdict + findings.

    A diagnostic for the content pipeline — same normalization + scanners the
    gateway uses. Exit code: 0 allow/warn, 2 strip, 3 block (scriptable).
    """
    import sys

    from ..detect import ContentGate
    from ..detect.scanners import default_scanners

    if file is not None:
        content = file.read_text(encoding="utf-8", errors="replace")
    elif stdin or text is None:
        content = sys.stdin.read()
    else:
        content = text
    if not content:
        raise _err("no input — pass TEXT, --file, or --stdin")

    try:
        settings = load_settings(config)
    except Exception as exc:  # noqa: BLE001
        raise _err(f"config invalid: {exc}")

    if show_variants:
        from ..normalize import normalize_variants

        for v in normalize_variants(
            content,
            max_unwrap_depth=settings.scanner.normalize.max_unwrap_depth,
            max_variants=settings.scanner.normalize.max_variants,
        ):
            tag = "+".join(v.passes) or "original"
            typer.echo(f"  [{tag} d{v.depth}] {v.text[:120]!r}")

    gate = ContentGate(
        default_scanners(settings),
        mode=settings.mode,
        max_unwrap_depth=settings.scanner.normalize.max_unwrap_depth,
        max_variants=settings.scanner.normalize.max_variants,
        scan_timeout_s=settings.scanner.scan_timeout_s,
    )
    result = gate.scan_text(content)

    colors = {"allow": typer.colors.GREEN, "warn": typer.colors.YELLOW,
              "strip": typer.colors.YELLOW, "ask": typer.colors.YELLOW,
              "block": typer.colors.RED}
    typer.secho(f"verdict: {result.verdict}", fg=colors.get(result.verdict), bold=True)
    if result.block_reason:
        typer.echo(f"reason:  {result.block_reason}")
    if not result.enforced:
        typer.secho("(audit mode — observed, not enforced)", fg=typer.colors.BLUE)
    for f in result.findings:
        tags = " ".join(x for x in (f.get("owasp"), f.get("mitre")) if x)
        typer.echo(f"  - {f['scanner']}/{f['rule_id']} [{f['severity']}] {tags}".rstrip())
    if result.redaction:
        typer.echo(f"redaction: {result.redaction}")
    raise typer.Exit({"block": 3, "strip": 2}.get(result.verdict, 0))


@policy_app.command("check")
def policy_check(
    actor: str = typer.Argument(..., help="agent SPIFFE id, e.g. spiffe://acme/agent/claude-code"),
    tool: str = typer.Argument(..., help="tool name, e.g. read_file"),
    arg: list[str] = typer.Option([], "--arg", "-a", help="argument as key=value (repeatable)"),
    policy_file: Path = typer.Option(
        Path("policies/default-deny.yaml"), "--policy", help="tool policy YAML"),
) -> None:
    """Check whether an identity may call a tool with given args (L4 diagnostic).

    Exit code: 0 allow, 3 deny. Args parse as key=value; values that look like
    ints are coerced.
    """
    from ..capability import ToolCall, ToolPolicy

    if not policy_file.exists():
        raise _err(f"policy file not found: {policy_file}")
    args: dict = {}
    for pair in arg:
        key, _, value = pair.partition("=")
        args[key] = int(value) if value.lstrip("-").isdigit() else value

    policy = ToolPolicy.from_yaml(policy_file)
    decision = policy.check(ToolCall(actor=actor, tool=tool, args=args))
    if decision.allowed:
        typer.secho("allow", fg=typer.colors.GREEN, bold=True)
        raise typer.Exit(0)
    typer.secho(f"deny  {decision.block_reason}", fg=typer.colors.RED, bold=True)
    for f in decision.findings:
        tags = " ".join(x for x in (f.get("owasp"), f.get("mitre")) if x)
        typer.echo(f"  - {f['scanner']}/{f['rule_id']} [{f['severity']}] {tags}".rstrip())
    raise typer.Exit(3)


@policy_app.command("show")
def policy_show(
    policy_file: Path = typer.Option(
        Path("policies/default-deny.yaml"), "--policy", help="tool policy YAML"),
) -> None:
    """List identities and their allowed/denied tools."""
    from ..capability import ToolPolicy

    if not policy_file.exists():
        raise _err(f"policy file not found: {policy_file}")
    policy = ToolPolicy.from_yaml(policy_file)
    for actor, ap in policy._config.agents.items():  # noqa: SLF001 — CLI inspection
        typer.secho(actor, fg=typer.colors.CYAN, bold=True)
        for rule in ap.allow:
            constrained = ",".join(rule.args) if rule.args else "no arg constraints"
            typer.echo(f"  allow {rule.tool} ({constrained})")
        for rule in ap.deny:
            typer.echo(f"  deny  {rule.tool}")
        if not ap.allow and not ap.deny:
            typer.echo("  (deny-all)")


@mcp_app.command("review")
def mcp_review(
    tools_json: Path = typer.Argument(..., help="MCP tools/list JSON (array of {name, description, inputSchema})"),
    config: Path = typer.Option(None, "--config", "-c", help="config YAML (scanner mode)"),
    pins: Path = typer.Option(Path("data/tool_pins.json"), "--pins", help="descriptor pin store"),
) -> None:
    """Pin + poison-scan advertised MCP tools. Exit 3 if any tool is withheld."""
    from ..detect import ContentGate
    from ..detect.scanners import default_scanners
    from ..mcp import ToolDescriptor, ToolPinner
    from ..mcp.descriptors import scan_descriptor

    try:
        settings = load_settings(config)
    except Exception as exc:  # noqa: BLE001
        raise _err(f"config invalid: {exc}")
    try:
        tools = json.loads(tools_json.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise _err(f"cannot read tools JSON: {exc}")

    gate = ContentGate(default_scanners(settings), mode=settings.mode)
    pinner = ToolPinner(pins)
    blocked = 0
    for t in tools:
        desc = ToolDescriptor(t.get("name", "?"), t.get("description", ""),
                              t.get("inputSchema") or t.get("input_schema"))
        poison = scan_descriptor(desc, gate)
        drift = pinner.check(desc) if poison.allowed else poison
        decision = poison if not poison.allowed else drift
        if decision.allowed:
            typer.secho(f"allow  {desc.name}", fg=typer.colors.GREEN)
        else:
            blocked += 1
            typer.secho(f"block  {desc.name}  {decision.block_reason}", fg=typer.colors.RED)
    if blocked:
        raise typer.Exit(3)


@killswitch_app.command("engage")
def killswitch_engage(
    reason: str = typer.Option(None, "--reason", help="why (recorded in status + receipt)"),
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Engage the kill switch: every mediated request denies until disengage.

    Cross-process by design — the sentinel file under data/ is the mechanism,
    so a running gateway sees the engagement immediately."""
    from ..runtime import Runtime

    try:
        runtime = Runtime(config, data_dir=data_dir)
    except Exception as exc:  # noqa: BLE001
        raise _err(f"refusing to start: {exc}")
    status = runtime.killswitch.engage("cli", reason=reason)
    runtime.close()
    typer.secho(f"kill switch ENGAGED (deny-all): {json.dumps(status)}",
                fg=typer.colors.RED, bold=True)


@killswitch_app.command("disengage")
def killswitch_disengage(
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Lift the kill switch (receipted)."""
    from ..runtime import Runtime

    try:
        runtime = Runtime(config, data_dir=data_dir)
    except Exception as exc:  # noqa: BLE001
        raise _err(f"refusing to start: {exc}")
    status = runtime.killswitch.disengage()
    runtime.close()
    typer.secho(f"kill switch disengaged: {json.dumps(status)}", fg=typer.colors.GREEN)


@killswitch_app.command("status")
def killswitch_status(
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
    sentinel_dir: Path = typer.Option(
        None, "--sentinel-dir", help="sentinel location (default: data dir)"),
) -> None:
    """Print kill-switch state (exit 3 when engaged — scriptable)."""
    from ..killswitch import KillSwitch

    status = KillSwitch(sentinel_dir or data_dir).status()
    typer.echo(json.dumps(status, indent=2))
    if status["engaged"]:
        raise typer.Exit(3)


def _boot_memory(config: Path | None, data_dir: Path):
    """Boot the runtime (fail-closed) and return (runtime, memory_guard).

    The guard needs the ledger (every read/write is receipted) and the
    signing key, so `al memory` runs against a full runtime. The CLI acts in
    the operator/mediator context — protected keys are writable here."""
    from ..runtime import Runtime

    try:
        runtime = Runtime(config, data_dir=data_dir)
    except Exception as exc:  # noqa: BLE001 — boot is fail-closed
        raise _err(f"refusing to start: {exc}")
    if not runtime.settings.memory.enabled:
        runtime.close()
        raise _err("memory guard is disabled (memory.enabled=false, audit only)")
    return runtime, runtime.memory_guard


def _echo_findings(findings: list[dict]) -> None:
    for f in findings:
        tags = " ".join(x for x in (f.get("owasp"), f.get("mitre")) if x)
        typer.echo(f"  - {f['scanner']}/{f['rule_id']} [{f['severity']}] {tags}".rstrip())


@memory_app.command("put")
def memory_put(
    key: str = typer.Argument(..., help="memory key, e.g. notes/todo or system/prompt"),
    value: str = typer.Argument(None, help="value (or --file / --stdin)"),
    file: Path = typer.Option(None, "--file", "-f", help="read value from a file"),
    stdin: bool = typer.Option(False, "--stdin", help="read value from stdin"),
    actor: str = typer.Option(None, "--actor", help="acting identity (default: mediator/operator)"),
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Guarded memory write. Exit: 0 stored, 2 stored redacted, 3 blocked."""
    import sys

    from ..runtime import MEDIATOR_ACTOR

    if file is not None:
        content = file.read_text(encoding="utf-8", errors="replace")
    elif stdin or value is None:
        content = sys.stdin.read()
    else:
        content = value
    if not content:
        raise _err("no value — pass VALUE, --file, or --stdin")

    runtime, guard = _boot_memory(config, data_dir)
    result = guard.write(actor or MEDIATOR_ACTOR, key, content)
    runtime.close()
    if result.allowed and not result.redaction:
        typer.secho(f"stored {key}", fg=typer.colors.GREEN)
        raise typer.Exit(0)
    if result.allowed:
        typer.secho(f"stored {key} (redacted: {result.redaction})", fg=typer.colors.YELLOW)
        raise typer.Exit(2)
    typer.secho(f"block  {result.decision.block_reason}", fg=typer.colors.RED, bold=True)
    _echo_findings(result.decision.findings)
    raise typer.Exit(3)


@memory_app.command("get")
def memory_get(
    key: str = typer.Argument(..., help="memory key"),
    actor: str = typer.Option(None, "--actor", help="acting identity (default: mediator/operator)"),
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Guarded memory read. Exit: 0 delivered (or absent), 3 blocked."""
    from ..runtime import MEDIATOR_ACTOR

    runtime, guard = _boot_memory(config, data_dir)
    result = guard.read(actor or MEDIATOR_ACTOR, key)
    runtime.close()
    if not result.allowed:
        typer.secho(f"block  {result.decision.block_reason}", fg=typer.colors.RED, bold=True)
        _echo_findings(result.decision.findings)
        raise typer.Exit(3)
    if result.value is None:
        typer.secho(f"(no entry {key})", fg=typer.colors.YELLOW)
        raise typer.Exit(0)
    typer.echo(result.value)


@memory_app.command("list")
def memory_list(
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """List memory keys with hashes and protection status (unscreened view)."""
    runtime, guard = _boot_memory(config, data_dir)
    entries = guard._store.entries()  # noqa: SLF001 — CLI inspection
    runtime.close()
    if not entries:
        typer.echo("(memory empty)")
        return
    for key, e in sorted(entries.items()):
        mark = "protected" if guard.is_protected(key) else ""
        typer.echo(f"{key}  {e.sha256[:23]}  {e.actor}  {e.ts}  {mark}".rstrip())


@memory_app.command("snapshot")
def memory_snapshot(
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Capture the current store + baselines as a known-good snapshot."""
    from ..runtime import MEDIATOR_ACTOR

    runtime, guard = _boot_memory(config, data_dir)
    info = guard.snapshot(MEDIATOR_ACTOR)
    runtime.close()
    typer.secho(f"snapshot {info.snapshot_id}  store={info.store_hash[:23]}  "
                f"({len(info.keys)} keys)", fg=typer.colors.GREEN)


@memory_app.command("rollback")
def memory_rollback(
    snapshot: str = typer.Option(None, "--snapshot", help="snapshot id (default: latest)"),
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Restore memory to a known-good snapshot (before/after hashes shown)."""
    from ..runtime import MEDIATOR_ACTOR

    runtime, guard = _boot_memory(config, data_dir)
    try:
        info = guard.rollback(MEDIATOR_ACTOR, snapshot)
    except FileNotFoundError as exc:
        runtime.close()
        raise _err(str(exc))
    runtime.close()
    typer.secho(f"rolled back to {info.snapshot_id}", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"before {info.before_hash}")
    typer.echo(f"after  {info.after_hash}")
    typer.echo(f"restored keys: {', '.join(info.restored_keys) or '(none)'}")


@memory_app.command("verify")
def memory_verify(
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Integrity-check every protected key against its baseline. Exit 3 on tamper."""
    from ..runtime import MEDIATOR_ACTOR

    runtime, guard = _boot_memory(config, data_dir)
    tampered = guard.verify(MEDIATOR_ACTOR)
    runtime.close()
    if tampered:
        typer.secho(f"TAMPERED: {', '.join(tampered)}", fg=typer.colors.RED, bold=True)
        raise typer.Exit(3)
    typer.secho("integrity OK — all protected keys match baselines", fg=typer.colors.GREEN)


@memory_app.command("quarantine")
def memory_quarantine(
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """List quarantined payloads (metadata only; values stay in the file)."""
    runtime, guard = _boot_memory(config, data_dir)
    items = guard.quarantined()
    runtime.close()
    if not items:
        typer.echo("(quarantine empty)")
        return
    for q in items:
        typer.echo(f"{q['id']}  {q['key']}  {q['reason']}  {q['actor']}  {q['ts']}")


@mcp_app.command("proxy", context_settings={"allow_extra_args": True,
                                            "ignore_unknown_options": True})
def mcp_proxy(
    ctx: typer.Context,
    actor: str = typer.Option(..., "--actor", help="agent SPIFFE id the calls run as"),
    url: str = typer.Option(None, "--url", help="Streamable-HTTP MCP upstream (instead of a command)"),
    session: str = typer.Option("default", "--session", help="session id (taint/chain scope)"),
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Mediated MCP proxy: agent speaks JSON-RPC on OUR stdio; upstream is a
    subprocess (`al mcp proxy --actor ID -- npx server`) or an HTTP MCP server
    (`--url`). tools/list is pinned+poison-scanned, tools/call authorized,
    results scanned — every decision receipted."""
    import asyncio
    import sys
    import threading

    from ..mcp import HttpUpstream, McpSession, StdioUpstream, run_proxy
    from ..mcp.session import dump_line, parse_line
    from ..runtime import Runtime

    command = list(ctx.args)
    if command and command[0] == "--":
        command = command[1:]
    if bool(command) == bool(url):
        raise _err("pass exactly one upstream: -- <server command>  OR  --url http://...")

    try:
        runtime = Runtime(config, data_dir=data_dir)
    except Exception as exc:  # noqa: BLE001 — boot is fail-closed
        raise _err(f"refusing to start: {exc}")

    mcp_session = McpSession(runtime.mcp_mediator, actor=actor, session_id=session)
    upstream = HttpUpstream(url) if url else StdioUpstream(command)

    async def _run() -> None:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()

        def _stdin_reader() -> None:
            for line in sys.stdin:
                msg = parse_line(line)
                if msg is not None:
                    loop.call_soon_threadsafe(queue.put_nowait, msg)
            loop.call_soon_threadsafe(queue.put_nowait, None)

        threading.Thread(target=_stdin_reader, daemon=True).start()

        async def recv_agent():
            return await queue.get()

        async def send_agent(msg) -> None:
            sys.stdout.write(dump_line(msg))
            sys.stdout.flush()

        await run_proxy(mcp_session, upstream, recv_agent, send_agent)

    try:
        asyncio.run(_run())
    finally:
        runtime.close()


def _boot_skills(config: Path | None, data_dir: Path):
    from ..runtime import Runtime

    try:
        runtime = Runtime(config, data_dir=data_dir)
    except Exception as exc:  # noqa: BLE001 — boot is fail-closed
        raise _err(f"refusing to start: {exc}")
    if not runtime.settings.skills.enabled:
        runtime.close()
        raise _err("skill guard is disabled (skills.enabled=false, audit only)")
    return runtime, runtime.skill_guard


# Never descend into these when a directory is scanned — a skill tree does not
# keep its instruction files in a virtualenv or a .git objects dir, and walking
# them turns `al skill check ./repo` into a minutes-long crawl over files we
# would only reject on size anyway.
_SKILL_SCAN_PRUNE = frozenset({
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", "dist", "build",
})


def _expand_skill_targets(targets: list[Path], patterns: list[str]) -> list[Path]:
    """Expand any directory argument into the instruction files beneath it.

    A directory is walked recursively; a file is picked up when its name matches
    one of the configured ``skills.paths`` patterns (SKILL.md, CLAUDE.md, ...),
    so ``al skill check ./my-skills/`` scans a whole tree the way a single-file
    scanner cannot. Noise dirs (.git, node_modules, .venv, ...) are pruned. An
    explicit file argument is always kept — even if its name matches nothing,
    the operator asked for that file by name. Order is stable and de-duplicated,
    so a file reached both directly and via a directory is scanned (and pinned)
    exactly once.
    """
    import fnmatch
    import os

    names = [Path(p).name for p in patterns]
    out: list[Path] = []
    seen: set[Path] = set()

    def _add(p: Path) -> None:
        key = p.resolve()
        if key not in seen:
            seen.add(key)
            out.append(p)

    for target in targets:
        if target.is_dir():
            for root, dirs, found in os.walk(target):
                dirs[:] = sorted(d for d in dirs if d not in _SKILL_SCAN_PRUNE)
                for name in sorted(found):
                    if any(fnmatch.fnmatch(name, pat) for pat in names):
                        _add(Path(root) / name)
        else:
            _add(target)
    return out


@skill_app.command("check")
def skill_check(
    files: list[Path] = typer.Argument(
        None, help="instruction files, or directories to scan recursively "
                   "(default: skills.paths in the cwd)"),
    actor: str = typer.Option("agent", "--actor", help="identity the load runs as"),
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Screen + pin agent instruction files (SKILL.md, CLAUDE.md, .cursorrules).

    Accepts files or directories; a directory is walked recursively for files
    matching skills.paths (SKILL.md, CLAUDE.md, AGENTS.md, .cursorrules), so
    ``al skill check ./my-skills/`` scans a whole tree in one shot.

    Use it as a CI/pre-commit gate AND as the runtime load path — the pin is what
    a CI check alone cannot give you: it catches a file that was clean when you
    scanned it and hostile by the time the agent read it.

    Exit: 0 clean, 2 redacted, 3 poisoned/drifted.
    """
    from ..gateway.decision import BlockReason

    runtime, guard = _boot_skills(config, data_dir)
    patterns = list(runtime.settings.skills.paths)
    requested = [Path(f) for f in files] if files else [Path(p) for p in patterns]
    targets = _expand_skill_targets(requested, patterns)
    if not targets:
        runtime.close()
        typer.secho("no instruction files found to scan", fg=typer.colors.YELLOW)
        raise typer.Exit(0)

    worst = 0
    for path in targets:
        out = guard.load(path, actor=actor)
        if not path.exists():
            typer.echo(f"skip   {path} (absent)")
            continue
        if not out.allowed:
            reason = out.decision.block_reason
            typer.secho(f"BLOCK  {path}  {reason}", fg=typer.colors.RED, bold=True)
            _echo_findings(out.decision.findings)
            if reason == BlockReason.SKILL_DRIFT:
                typer.echo(f"       re-approve with: al skill approve {path}")
            worst = max(worst, 3)
        elif out.redaction:
            typer.secho(f"strip  {path}  redacted: {out.redaction}",
                        fg=typer.colors.YELLOW)
            worst = max(worst, 2)
        else:
            typer.secho(f"ok     {path}  pinned", fg=typer.colors.GREEN)
    runtime.close()
    raise typer.Exit(worst)


@skill_app.command("approve")
def skill_approve(
    file: Path = typer.Argument(..., help="instruction file to re-pin"),
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Operator re-pins a drifted file after reviewing it (un-blocks the load).

    Refuses to pin a file the content gate blocks — approving a poisoned file
    would make the attack the trusted baseline."""
    from ..gateway.decision import BlockReason
    from ..skills.guard import read_file

    runtime, guard = _boot_skills(config, data_dir)
    if not file.exists():
        runtime.close()
        raise _err(f"no such file: {file}")
    # Read it exactly the way the guard reads it, or the pin will not match; and
    # screen it with the guard's OWN (skill-tuned) gate via load(), so approve
    # cannot pin a file that load() would then reject as poisoned. A DRIFT block
    # is the expected case here — that is precisely what we are approving.
    text = read_file(file)
    out = guard.load(file)
    if not out.allowed and out.decision.block_reason != BlockReason.SKILL_DRIFT:
        runtime.close()
        raise _err(f"refusing to pin a file the gate blocks "
                   f"({out.decision.block_reason}) — fix the file, do not approve it")
    guard.pinner.approve(file, text)
    runtime.close()
    typer.secho(f"pinned {file}", fg=typer.colors.GREEN)


@skill_app.command("verify")
def skill_verify(
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Re-check every pinned instruction file against its digest. Exit 3 on drift."""
    runtime, guard = _boot_skills(config, data_dir)
    drifted = guard.verify()
    runtime.close()
    if drifted:
        typer.secho(f"DRIFTED: {', '.join(drifted)}", fg=typer.colors.RED, bold=True)
        raise typer.Exit(3)
    typer.secho("all pinned instruction files match their baselines",
                fg=typer.colors.GREEN)


@skill_app.command("list")
def skill_list(
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """List pinned instruction files."""
    runtime, guard = _boot_skills(config, data_dir)
    pins = guard.pinner.all_pins()
    runtime.close()
    if not pins:
        typer.echo("(no instruction files pinned — run `al skill check`)")
        return
    for path, entry in sorted(pins.items()):
        typer.echo(f"{entry['digest'][:23]}  {entry['approved_ts']}  {path}")


def _mine_candidates(data_dir: Path, min_hits: int):
    """Mine from the canonical ledger + the memory quarantine.

    Receipts carry no plaintext by design, so payload patterns can only come
    from the quarantine (which preserves hostile payloads for exactly this)."""
    from ..learn import mine

    ledger = data_dir / "ledger.jsonl"
    if not ledger.exists():
        raise _err(f"no ledger at {ledger}")
    receipts = [json.loads(line) for line in
                ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    quarantine_path = data_dir / "memory_quarantine.json"
    quarantine = (json.loads(quarantine_path.read_text(encoding="utf-8"))
                  if quarantine_path.exists() else [])
    return mine(receipts, quarantine, min_hits=min_hits)


@learn_app.command("mine")
def learn_mine(
    min_hits: int = typer.Option(2, "--min-hits", help="noise floor: blocks needed to propose"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Propose candidate rules from what the plane blocked. Nothing is enforced:
    candidates are inert until `al learn approve` signs them."""
    candidates = _mine_candidates(data_dir, min_hits)
    if not candidates:
        typer.echo("(no candidates — nothing was blocked often enough)")
        return
    for c in candidates:
        typer.secho(f"{c.rule_id}", fg=typer.colors.CYAN, bold=True)
        typer.echo(f"  pattern:   {c.pattern}")
        typer.echo(f"  action:    {c.action} [{c.severity}] "
                   f"{' '.join(x for x in (c.owasp, c.mitre) if x)}".rstrip())
        typer.echo(f"  rationale: {c.rationale}")
        if c.source_seqs:
            typer.echo(f"  receipts:  {c.source_seqs}")
    typer.echo(f"\n{len(candidates)} candidate(s). Approve with: "
               f"al learn approve --rule <rule_id> [--rule ...]")


@learn_app.command("approve")
def learn_approve(
    rules: list[str] = typer.Option([], "--rule", "-r", help="rule_id to approve (repeatable)"),
    approved_by: str = typer.Option(..., "--by", help="who approved (recorded in the bundle)"),
    bundle_id: str = typer.Option(None, "--bundle-id", help="default: derived from the count"),
    min_hits: int = typer.Option(2, "--min-hits"),
    tests_dir: Path = typer.Option(Path("tests/learned"), "--tests-dir",
                                   help="where the regression tests are written"),
    output: Path = typer.Option(None, "--out", "-o", help="bundle path (default: data/rules/<id>.json)"),
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """The human-review gate: sign the approved rules and generate their tests.

    Only the named rules are promoted. The bundle is Ed25519-signed with the
    mediator key; the runtime refuses to load it if the signature does not
    check out."""
    from ..learn import build_bundle, generate_tests
    from ..runtime import Runtime

    if not rules:
        raise _err("approve at least one rule: --rule <rule_id>")
    candidates = {c.rule_id: c for c in _mine_candidates(data_dir, min_hits)}
    unknown = [r for r in rules if r not in candidates]
    if unknown:
        raise _err(f"not a mined candidate: {', '.join(unknown)} "
                   "(run `al learn mine` to see the list)")
    approved = [candidates[r] for r in rules]

    try:
        runtime = Runtime(config, data_dir=data_dir)
    except Exception as exc:  # noqa: BLE001 — boot is fail-closed
        raise _err(f"refusing to start: {exc}")
    bid = bundle_id or f"bundle-{len(approved):02d}-{approved[0].rule_id[:16]}"
    doc = build_bundle(approved, runtime.signing_key, bundle_id=bid,
                       approved_by=approved_by)
    pubkey = Path(str(runtime.settings.keys.signing_key_path) + ".pub")
    runtime.close()

    out = output or (data_dir / "rules" / f"{bid}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    test_file = generate_tests(doc, bundle_path=out, pubkey_path=pubkey,
                               out_dir=tests_dir)

    typer.secho(f"signed bundle {bid} ({len(approved)} rule(s)) -> {out}",
                fg=typer.colors.GREEN, bold=True)
    typer.echo(f"regression tests -> {test_file}")
    typer.echo("enforce it by adding to your config:")
    typer.echo(f"  learn:\n    rule_bundle: {out.as_posix()}")


@learn_app.command("verify")
def learn_verify(
    bundle: Path = typer.Argument(..., help="rule bundle .json"),
    pubkey: Path = typer.Option(Path("keys/mediator_ed25519.pub"), "--pubkey"),
) -> None:
    """Verify a rule bundle with the standalone verifier (exit 1 on failure)."""
    from al_verify.cli import main as verify_main

    raise typer.Exit(verify_main([str(bundle), "--pubkey", str(pubkey)]))


@app.command("export")
def export_siem(
    output: Path = typer.Option(None, "--out", "-o", help="write here (default: stdout)"),
    ledger: Path = typer.Option(DEFAULT_DATA / "ledger.jsonl", "--ledger", help="JSONL ledger"),
    verdict: str = typer.Option(None, "--verdict", help="only this verdict (e.g. block)"),
    fmt: str = typer.Option("siem", "--format", help="siem (ECS/MITRE NDJSON)"),
) -> None:
    """Export the ledger as MITRE-tagged SIEM events (newline-delimited JSON).

    Reads the canonical JSONL (not the mirror) so an export is always of the
    signed truth; each event carries record_hash + sig so an analyst can pull
    the receipt and verify it independently."""
    import sys

    from ..audit.siem import export as siem_export

    if fmt != "siem":
        raise _err(f"unknown format: {fmt}")
    if not ledger.exists():
        raise _err(f"no ledger at {ledger}")
    receipts = [json.loads(line) for line in
                ledger.read_text(encoding="utf-8").splitlines() if line.strip()]
    if verdict:
        receipts = [r for r in receipts if r.get("verdict") == verdict]

    if output is None:
        siem_export(receipts, sys.stdout)
        return
    with output.open("w", encoding="utf-8") as fh:
        count = siem_export(receipts, fh)
    typer.secho(f"exported {count} event(s) -> {output}", fg=typer.colors.GREEN)


@app.command()
def gateway(
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    host: str = typer.Option("0.0.0.0", "--host"),
    port: int = typer.Option(8443, "--port", help="fetch + reverse proxy port"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Run the data-plane gateway (fetch + reverse proxy + CONNECT forward proxy)."""
    import uvicorn

    from ..gateway.web import create_gateway_app
    from ..runtime import Runtime

    try:
        runtime = Runtime(config, data_dir=data_dir)
        application = create_gateway_app(
            runtime, forward_listen=runtime.settings.gateway.forward_listen
        )
    except Exception as exc:  # noqa: BLE001 — boot is fail-closed
        raise _err(f"refusing to start: {exc}")
    if runtime.killswitch.install_signal_handler():
        typer.echo("kill switch signal source armed (SIGUSR1 -> deny-all)")
    uvicorn.run(application, host=host, port=port)


@app.command("verify-receipt")
def verify_receipt(
    receipt: Path = typer.Argument(..., help="receipt .json or .jsonl ledger"),
    pubkey: str = typer.Option("keys/mediator_ed25519.pub", "--pubkey", help="public key file or hex"),
) -> None:
    """Verify a receipt/ledger via the standalone al-verify implementation."""
    from al_verify.cli import main as verify_main

    raise typer.Exit(verify_main([str(receipt), "--pubkey", pubkey]))


@app.command()
def healthz(
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir", help="ledger/registry location"),
) -> None:
    """Boot the runtime and print the health payload (config + chain verify)."""
    from ..runtime import Runtime

    try:
        runtime = Runtime(config, data_dir=data_dir)
    except Exception as exc:  # noqa: BLE001 — boot is fail-closed
        raise _err(f"refusing to start: {exc}")
    payload = runtime.healthz()
    runtime.close()
    typer.echo(json.dumps(payload, indent=2))
    if payload["status"] != "healthy":
        raise typer.Exit(1)


@app.command()
def run(
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8888, "--port"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Run the control-plane API (Phase 0: /healthz)."""
    import uvicorn

    from ..app import create_app

    try:
        application = create_app(config, data_dir=data_dir)
    except Exception as exc:  # noqa: BLE001
        raise _err(f"refusing to start: {exc}")
    uvicorn.run(application, host=host, port=port)


if __name__ == "__main__":  # pragma: no cover
    app()
