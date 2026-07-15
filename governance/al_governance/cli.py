"""``al-gov`` — multi-org governance CLI.

Kept out of the core ``al`` CLI on purpose: the core must never import the
governance layer. Commands: org create/list, user add/list/revoke,
attest export/verify, cost, serve.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

app = typer.Typer(
    name="al-gov",
    help="AgentLighthouse governance — orgs, RBAC, budgets, signed posture attestation.",
    no_args_is_help=True,
    add_completion=False,
)
org_app = typer.Typer(help="Manage orgs (tenants).")
app.add_typer(org_app, name="org")
user_app = typer.Typer(help="Manage users + roles (admin/operator/viewer).")
app.add_typer(user_app, name="user")
attest_app = typer.Typer(help="Signed per-org posture attestation.")
app.add_typer(attest_app, name="attest")

DEFAULT_DATA = Path("data")


def _err(msg: str) -> "typer.Exit":
    typer.secho(f"error: {msg}", fg=typer.colors.RED, err=True)
    return typer.Exit(1)


def _store(data_dir: Path):
    from .tenancy import OrgStore

    return OrgStore(data_dir / "orgs.json")


@org_app.command("create")
def org_create(
    org: str = typer.Argument(..., help="org slug, e.g. acme (matches spiffe://acme/...)"),
    display_name: str = typer.Option(None, "--name", help="human-readable name"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Create a tenant. The slug must match the org in its agents' SPIFFE ids."""
    try:
        created = _store(data_dir).create_org(org, display_name=display_name)
    except ValueError as exc:
        raise _err(str(exc))
    typer.secho(f"created org {created['org']}", fg=typer.colors.GREEN)


@org_app.command("list")
def org_list(data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir")) -> None:
    """List tenants."""
    orgs = _store(data_dir).orgs()
    if not orgs:
        typer.echo("(no orgs — create one with: al-gov org create <slug>)")
        return
    for o in orgs:
        typer.echo(f"{o['org']:20} {o['display_name']:30} {o['created_ts']}")


@user_app.command("add")
def user_add(
    subject: str = typer.Argument(..., help="user id, e.g. alice@acme"),
    org: str = typer.Option(None, "--org", help="tenant (omit with --fleet)"),
    role: str = typer.Option("viewer", "--role", help="admin | operator | viewer"),
    fleet: bool = typer.Option(False, "--fleet", help="cross-org admin (no single org)"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Add a user and print its token ONCE (stored hashed, never recoverable)."""
    if fleet and org:
        raise _err("--fleet is cross-org; do not also pass --org")
    if not fleet and not org:
        raise _err("pass --org <tenant> (or --fleet for a cross-org admin)")
    try:
        issued = _store(data_dir).add_user(subject, org=None if fleet else org, role=role)
    except ValueError as exc:
        raise _err(str(exc))
    scope = "fleet (all orgs)" if fleet else f"org {org}"
    typer.secho(f"created {subject} — {role} in {scope}", fg=typer.colors.GREEN)
    typer.secho("token (shown once, store it now):", fg=typer.colors.YELLOW)
    typer.echo(issued.token)


@user_app.command("list")
def user_list(
    org: str = typer.Option(None, "--org", help="only this tenant"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """List users (never their tokens)."""
    users = _store(data_dir).users(org)
    if not users:
        typer.echo("(no users)")
        return
    for u in users:
        typer.echo(f"{u.subject:24} {(u.org or 'FLEET'):12} {u.role:9} {u.created_ts}")


@user_app.command("revoke")
def user_revoke(
    subject: str = typer.Argument(...),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Revoke a user (its token stops authenticating immediately)."""
    if not _store(data_dir).revoke(subject):
        raise _err(f"no such user: {subject}")
    typer.secho(f"revoked {subject}", fg=typer.colors.GREEN)


@attest_app.command("export")
def attest_export(
    org: str = typer.Argument(..., help="tenant to attest"),
    output: Path = typer.Option(None, "--out", "-o", help="write here (default: stdout)"),
    since: str = typer.Option(None, "--since", help="ISO-8601 lower bound"),
    until: str = typer.Option(None, "--until", help="ISO-8601 upper bound"),
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Export a signed posture attestation for an org (verifiable by al-verify)."""
    from al_core.runtime import Runtime

    from .attestation import build_attestation

    try:
        runtime = Runtime(config, data_dir=data_dir)
    except Exception as exc:  # noqa: BLE001 — boot is fail-closed
        raise _err(f"refusing to start: {exc}")
    doc = build_attestation(runtime, org, since=since, until=until)
    runtime.close()
    blob = json.dumps(doc, indent=2, ensure_ascii=False)
    if output is None:
        typer.echo(blob)
        return
    output.write_text(blob + "\n", encoding="utf-8")
    typer.secho(
        f"attestation for {org} -> {output}  (evidence level {doc['evidence_level']}, "
        f"{doc['evidence']['events']} events)", fg=typer.colors.GREEN)


@attest_app.command("verify")
def attest_verify(
    attestation: Path = typer.Argument(..., help="attestation .json"),
    pubkey: Path = typer.Option(Path("keys/mediator_ed25519.pub"), "--pubkey"),
) -> None:
    """Verify an attestation with the standalone verifier (exit 1 on failure)."""
    from al_verify.cli import main as verify_main

    raise typer.Exit(verify_main([str(attestation), "--pubkey", str(pubkey)]))


@app.command()
def cost(
    org: str = typer.Option(None, "--org", help="tenant (omit = whole fleet)"),
    usd_per_mtok: float = typer.Option(None, "--usd-per-mtok", help="blended rate"),
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Today's spend (requests + tokens) per virtual key, scoped to an org."""
    from al_core.runtime import Runtime

    from .billing import cost_report

    try:
        runtime = Runtime(config, data_dir=data_dir)
    except Exception as exc:  # noqa: BLE001
        raise _err(f"refusing to start: {exc}")
    report = cost_report(runtime.ledger.db, runtime.vkeys, org=org,
                         usd_per_mtok=usd_per_mtok)
    runtime.close()
    typer.echo(json.dumps(report, indent=2))


@app.command()
def serve(
    config: Path = typer.Option(None, "--config", "-c", help="config YAML"),
    host: str = typer.Option("127.0.0.1", "--host", help="bind (control-net only)"),
    port: int = typer.Option(8888, "--port"),
    data_dir: Path = typer.Option(DEFAULT_DATA, "--data-dir"),
) -> None:
    """Serve the governed control plane (multi-org auth + dashboard + governance API)."""
    import uvicorn

    from .app import create_governed_app

    try:
        application = create_governed_app(config, data_dir=data_dir)
    except Exception as exc:  # noqa: BLE001 — boot is fail-closed
        raise _err(f"refusing to start: {exc}")
    typer.secho(f"governed control plane on http://{host}:{port}/dashboard",
                fg=typer.colors.GREEN)
    uvicorn.run(application, host=host, port=port)


if __name__ == "__main__":  # pragma: no cover
    app()
