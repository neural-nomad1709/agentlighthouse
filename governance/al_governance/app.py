"""Governed control plane: the core app + multi-org auth and governance routes.

This is the core control-plane app with two changes:

* its authenticator is the :class:`OrgStore` directory, so every request
  resolves to a real user's Principal (org + role) — and core's own scoping
  then confines every evidence query to that org;
* it adds the governance-only routes: ``/api/orgs``, ``/api/users``,
  ``/api/attestation``, ``/api/cost``.

Core never imports this module. The isolation is enforced *below* here, so a
bug in governance can only narrow what a caller sees, never widen it.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from al_core.app import bearer, create_app

from .attestation import build_attestation
from .billing import cost_report
from .tenancy import OrgStore


def create_governed_app(
    config_path: str | Path | None = None,
    *,
    data_dir: str | Path = "data",
    store_path: Path | None = None,
    **overrides,
) -> FastAPI:
    data = Path(data_dir)
    store = OrgStore(store_path or data / "orgs.json")
    app = create_app(config_path, data_dir=data,
                     authenticator=store.authenticate, **overrides)
    runtime = app.state.runtime
    app.state.org_store = store

    def _principal(request: Request):
        return store.authenticate(bearer(request.headers.get("authorization")))

    def _deny(p, capability: str) -> JSONResponse | None:
        if p is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401,
                                headers={"WWW-Authenticate": "Bearer"})
        if not p.can(capability):
            return JSONResponse(
                {"error": "forbidden", "detail": f"capability '{capability}' required"},
                status_code=403)
        return None

    @app.get("/api/orgs")
    def api_orgs(request: Request) -> JSONResponse:
        """Orgs visible to the caller. A tenant sees only its own — the org
        list names your competitors, so it is itself tenant-sensitive."""
        p = _principal(request)
        if (err := _deny(p, "view")) is not None:
            return err
        orgs = store.orgs()
        if p.org is not None:
            orgs = [o for o in orgs if o["org"] == p.org]
        return JSONResponse({"orgs": orgs})

    @app.get("/api/users")
    def api_users(request: Request) -> JSONResponse:
        """Users in the caller's org (fleet admin: all). Token hashes are never
        returned — not even to an admin; a hash is still a credential shape."""
        p = _principal(request)
        if (err := _deny(p, "configure")) is not None:
            return err
        users = store.users(p.org)
        return JSONResponse({"users": [
            {"subject": u.subject, "org": u.org, "role": u.role,
             "created_ts": u.created_ts} for u in users
        ]})

    @app.get("/api/attestation")
    def api_attestation(request: Request, org: str | None = None,
                        since: str | None = None, until: str | None = None) -> JSONResponse:
        """Signed posture attestation for the caller's org (fleet admin may name
        one). Verifiable by anyone with `al-verify` — no runtime required."""
        p = _principal(request)
        if (err := _deny(p, "attest")) is not None:
            return err
        target = p.org if p.org is not None else org
        if target is None:
            return JSONResponse(
                {"error": "org_required",
                 "detail": "fleet admin must name an org: ?org=<name>"},
                status_code=400)
        if p.org is not None and org is not None and org != p.org:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return JSONResponse(build_attestation(runtime, target, since=since, until=until))

    @app.get("/api/cost")
    def api_cost(request: Request, usd_per_mtok: float | None = None) -> JSONResponse:
        """Today's spend for the caller's org (fleet admin: the whole fleet)."""
        p = _principal(request)
        if (err := _deny(p, "view")) is not None:
            return err
        return JSONResponse(cost_report(
            runtime.ledger.db, runtime.vkeys, org=p.org, usd_per_mtok=usd_per_mtok))

    return app


__all__ = ["create_governed_app"]
