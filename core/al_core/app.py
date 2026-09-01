"""Control-plane HTTP surface (health, evidence API, kill switch, dashboard).

Runs on the control network. ``/healthz`` reports config validity and the
receipt chain-verify status. The read-only evidence API (``/api/*``) and the
static dashboard (``/dashboard``) let an operator see what the plane decided —
verdict/action breakdowns, block reasons, and recent receipts — sourced from
the SQLite **mirror** (the JSONL ledger stays canonical). The one control
action here is the kill switch (``/api/killswitch``).

**Tenancy (Phase 6).** Every request resolves to a :class:`Principal` and every
evidence query is scoped to ``principal.org``. A principal bound to one org
cannot reach another org's events through *any* endpoint — including a direct
``/api/receipts/{seq}`` fetch, which returns 404 rather than leaking existence.
Cross-org (fleet) scope is only ever granted to an ``org=None`` admin.

Authentication is injectable (``authenticator``). The default is single-tenant:
the admin API token grants a fleet admin. The governance layer
swaps in a multi-org user directory; the scoping enforced here does not change,
so a governance bug can only narrow what a caller sees, never widen it.
"""

from __future__ import annotations

import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .audit.pool import EvidencePool, RemotePlane
from .principal import Authenticator, Principal
from .runtime import Runtime

# The built dashboard (Vite → frontend/dist) is served at /dashboard. The repo
# root is two parents above al_core/.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DASHBOARD_DIST = _REPO_ROOT / "frontend" / "dist"


def bearer(authorization: str | None) -> str | None:
    scheme, _, token = (authorization or "").partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token.strip() else None


def admin_token_authenticator(expected: str) -> Authenticator:
    """Single-tenant default: the admin API token grants a fleet admin."""

    def authenticate(token: str | None) -> Principal | None:
        if token and secrets.compare_digest(token, expected):
            return Principal(subject="admin", role="admin", org=None)
        return None

    return authenticate


def create_app(
    config_path: str | Path | None = None,
    *,
    data_dir: str | Path = "data",
    authenticator: Authenticator | None = None,
    **overrides,
) -> FastAPI:
    runtime = Runtime(config_path, data_dir=data_dir, **overrides)
    authenticate = authenticator or admin_token_authenticator(
        runtime.settings.admin_api_token.get_secret_value())

    # Evidence reads go through a pool: this plane's own ledger plus, when
    # configured (control.dataplane_dir), the data plane's ledger opened
    # READ-ONLY over a shared volume. That is what puts gateway traffic on
    # the dashboard while each chain keeps exactly one writer.
    remotes: list[RemotePlane] = []
    dp_dir = runtime.settings.control.dataplane_dir
    if dp_dir is not None:
        remotes.append(RemotePlane(
            "data", dp_dir, runtime.settings.control.dataplane_pubkey))
    pool = EvidencePool("control" if remotes else "local",
                        runtime.ledger.db, remotes)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        runtime.start_config_watch()
        yield
        pool.close()
        runtime.close()

    app = FastAPI(title="AgentLighthouse", version="0.1.0", lifespan=lifespan)
    app.state.runtime = runtime

    def _principal(request: Request) -> Principal | None:
        return authenticate(bearer(request.headers.get("authorization")))

    def _unauthorized() -> JSONResponse:
        return JSONResponse(
            {"error": "unauthorized", "detail": "a valid API token is required"},
            status_code=401,
            headers={"WWW-Authenticate": "Bearer"},
        )

    def _forbidden(capability: str) -> JSONResponse:
        return JSONResponse(
            {"error": "forbidden", "detail": f"capability '{capability}' required"},
            status_code=403,
        )

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        payload = runtime.healthz()
        code = 200 if payload["status"] == "healthy" else 503
        return JSONResponse(payload, status_code=code)

    @app.get("/api/session")
    def api_session(request: Request) -> JSONResponse:
        """Who am I: role, capabilities, and the org(s) I may see."""
        p = _principal(request)
        if p is None:
            return _unauthorized()
        # A tenant sees only its own org in the picker; a fleet admin sees all.
        orgs = ([p.org] if p.org is not None
                else sorted(pool.org_counts().keys()))
        return JSONResponse({
            "authenticated": True,
            "subject": p.subject,
            "role": p.role,
            "capabilities": p.capabilities,
            "org": p.org,
            "orgs": orgs,
            "planes": pool.planes,
            "mode": runtime.settings.mode,
            "env": runtime.settings.env,
        })

    # -- kill switch (control action; requires the 'configure' capability) ----

    @app.get("/api/killswitch")
    def api_killswitch_status(request: Request) -> JSONResponse:
        p = _principal(request)
        if p is None:
            return _unauthorized()
        return JSONResponse(runtime.killswitch.status())

    @app.post("/api/killswitch")
    async def api_killswitch(request: Request) -> JSONResponse:
        """Engage (default) or disengage the kill switch. Engaging drills the
        whole data plane to deny-all; both transitions emit signed receipts.

        The switch is fleet-wide by nature — it stops the mediator, not one
        tenant — so it takes the 'configure' capability (admin only)."""
        p = _principal(request)
        if p is None:
            return _unauthorized()
        if not p.can("configure"):
            return _forbidden("configure")
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001 — empty body = engage
            body = {}
        if body.get("engage", True):
            status = runtime.killswitch.engage(
                "api", actor=f"user:{p.subject}", reason=body.get("reason"))
        else:
            status = runtime.killswitch.disengage(actor=f"user:{p.subject}")
        return JSONResponse(status)

    # -- HITL approvals (the operator side of the L4 gate) --------------------

    @app.get("/api/approvals")
    def api_approvals(request: Request) -> JSONResponse:
        """Pending approval requests, with age and time-to-lapse. A lapsed
        request never appears here: timeout is a denial, not a queue entry.
        Org-scoped like every other /api/* route: a tenant sees only requests
        filed by its own org's actors."""
        p = _principal(request)
        if p is None:
            return _unauthorized()
        from .audit.db import org_of

        gate = runtime.action_gate.hitl
        rows = [{
            "request_id": r.request_id,
            "actor": r.actor,
            "tool": r.tool,
            "detail": r.detail,
            "session": r.session,
            "age_s": gate.age_s(r.request_id),
            "remaining_s": gate.remaining_s(r.request_id),
            "timeout_s": r.timeout_s,
        } for r in gate.pending() if p.scope is None or org_of(r.actor) == p.scope]
        return JSONResponse({"count": len(rows), "approvals": rows})

    @app.post("/api/approvals/{request_id}")
    async def api_resolve_approval(request: Request, request_id: str) -> JSONResponse:
        """Resolve one pending approval (allow | deny). The resolving actor is
        recorded on the request and in a signed receipt. A lapsed or already-
        resolved request conflicts — existing semantics are preserved exactly:
        a timed-out request cannot be resolved, timeout remains a denial."""
        p = _principal(request)
        if p is None:
            return _unauthorized()
        if not p.can("approve"):
            return _forbidden("approve")
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001 — no body = no decision
            body = {}
        decision = body.get("decision")
        if decision not in ("allow", "deny"):
            return JSONResponse(
                {"error": "invalid_decision", "detail": "decision must be 'allow' or 'deny'"},
                status_code=422,
            )
        from .audit.db import org_of

        gate = runtime.action_gate.hitl
        req = gate.request(request_id)
        if req is None:
            return JSONResponse({"error": "not_found"}, status_code=404)
        if p.scope is not None and org_of(req.actor) != p.scope:
            # another tenant's request is *not found*, never leaked
            return JSONResponse({"error": "not_found"}, status_code=404)
        resolver = f"user:{p.subject}"
        resolved = (gate.approve(request_id, by=resolver) if decision == "allow"
                    else gate.deny(request_id, by=resolver))
        if not resolved:
            # lapsed (timeout is a denial) or already resolved
            return JSONResponse(
                {"error": "conflict", "status": gate.status(request_id)},
                status_code=409,
            )
        from .gateway.decision import finding

        allowed = decision == "allow"
        runtime.record(
            actor=resolver,
            action="mcp_tool_call",
            target=f"hitl:{request_id}",
            verdict="allow" if allowed else "block",
            block_reason=None if allowed else "HITL_DENIED",
            findings=[finding("hitl", "hitl.approved" if allowed else "hitl.denied",
                              "low" if allowed else "high", owasp="ASI09")],
        )
        return JSONResponse({
            "request_id": request_id,
            "status": gate.status(request_id),
            "resolved_by": resolver,
        })

    # -- read-only evidence API (org-scoped for every principal) --------------

    @app.get("/api/summary")
    def api_summary(request: Request) -> JSONResponse:
        p = _principal(request)
        if p is None:
            return _unauthorized()
        health = runtime.healthz()
        stats = pool.stats(p.scope)
        chains = pool.chains(health["chain"])
        return JSONResponse({
            "mode": health["mode"],
            "env": health["env"],
            "config_hash": health["config_hash"],
            "chain": health["chain"],
            "chains": chains,
            "killswitch": runtime.killswitch.status(),
            "org": p.org,
            **stats,
        })

    @app.get("/api/receipts")
    def api_receipts(
        request: Request,
        limit: int = 100,
        actor: str | None = None,
        action: str | None = None,
        verdict: str | None = None,
    ) -> JSONResponse:
        p = _principal(request)
        if p is None:
            return _unauthorized()
        receipts = pool.recent_filtered(
            limit=limit, actor=actor, action=action, verdict=verdict, org=p.scope,
        )
        return JSONResponse({"count": len(receipts), "receipts": receipts})

    @app.get("/api/chain")
    def api_chain(request: Request) -> JSONResponse:
        """Chain-verify status. The chain spans the whole ledger (it is one
        hash chain, by design), so a tenant sees only its integrity verdict —
        never another org's sequence numbers."""
        p = _principal(request)
        if p is None:
            return _unauthorized()
        chains = pool.chains(runtime.healthz()["chain"])
        if p.org is not None:  # tenants see integrity verdicts, never lengths
            chains = {plane: {"verified": c["verified"], "error": c["error"],
                              "reason": c.get("reason")}
                      for plane, c in chains.items()}
        local = chains[pool.local_plane]
        return JSONResponse({**local, "chains": chains})

    @app.get("/api/search")
    def api_search(
        request: Request,
        q: str | None = None,
        since: str | None = None,
        until: str | None = None,
        actor: str | None = None,
        action: str | None = None,
        verdict: str | None = None,
        org: str | None = None,
        limit: int = 100,
    ) -> JSONResponse:
        p = _principal(request)
        if p is None:
            return _unauthorized()
        # A tenant's org filter can only ever narrow *within* its own scope —
        # an org= parameter never widens it (that would be the whole attack).
        scope = p.scope if p.scope is not None else org
        if p.scope is not None and org is not None and org != p.scope:
            return JSONResponse({"count": 0, "receipts": []})
        receipts = pool.search(
            query=q, since=since, until=until, actor=actor,
            action=action, verdict=verdict, org=scope, limit=limit,
        )
        return JSONResponse({"count": len(receipts), "receipts": receipts})

    @app.get("/api/trends")
    def api_trends(request: Request, buckets: int = 24, span_hours: int = 24) -> JSONResponse:
        p = _principal(request)
        if p is None:
            return _unauthorized()
        buckets = max(1, min(buckets, 200))
        return JSONResponse({"series": pool.time_series(
            buckets=buckets, span_hours=max(1, span_hours), org=p.scope)})

    @app.get("/api/receipts/{seq}")
    def api_receipt(request: Request, seq: int, plane: str | None = None) -> JSONResponse:
        p = _principal(request)
        if p is None:
            return _unauthorized()
        if plane is not None and plane not in pool.planes:
            return JSONResponse({"error": "not_found"}, status_code=404)
        receipt = pool.receipt_by_seq(seq, p.scope, plane)
        if receipt is None:  # another tenant's seq is *not found*, never leaked
            return JSONResponse({"error": "not_found"}, status_code=404)
        return JSONResponse(receipt)

    @app.get("/api/verify/{seq}")
    def api_verify(request: Request, seq: int, plane: str | None = None) -> JSONResponse:
        p = _principal(request)
        if p is None:
            return _unauthorized()
        if not p.can("verify"):
            return _forbidden("verify")
        if plane is not None and plane not in pool.planes:
            return JSONResponse({"error": "not_found"}, status_code=404)
        receipt = pool.receipt_by_seq(seq, p.scope, plane)
        if receipt is None:
            return JSONResponse({"error": "not_found"}, status_code=404)
        # Verify this receipt's signature + record hash with the standalone
        # verifier (same code third parties run) — the audit "view trace"
        # check. Each plane signs with its own mediator key. The pool's plane
        # tag is presentation-only and must not enter the hashed body.
        from al_verify.verify import verify_receipt

        body = {k: v for k, v in receipt.items() if k != "plane"}
        try:
            key = pool.public_key_for(plane, runtime.public_key)
            verify_receipt(body, key)
            ok, error = True, None
        except Exception as exc:  # noqa: BLE001 — any failure = not verified
            ok, error = False, str(exc)
        return JSONResponse({
            "seq": seq, "plane": receipt.get("plane"), "verified": ok, "error": error,
            "record_hash": receipt.get("record_hash"),
            "prev_hash": receipt.get("prev_hash"),
            "sig": receipt.get("sig"),
        })

    # -- static dashboard (built Vite app) -----------------------------------

    @app.get("/dashboard", response_model=None)
    def dashboard_root() -> RedirectResponse | JSONResponse:
        if not (_DASHBOARD_DIST / "index.html").exists():
            return JSONResponse(
                {"error": "dashboard_not_built",
                 "detail": "run `npm --prefix frontend install && npm --prefix frontend "
                           "run build` to produce frontend/dist"},
                status_code=404,
            )
        return RedirectResponse(url="/dashboard/")

    if (_DASHBOARD_DIST / "index.html").exists():
        # html=True serves index.html at the mount root and 404s unknown paths;
        # the SPA has no client-side routing, so that is sufficient. The page
        # ships no secrets — its /api/* calls carry the operator's bearer token.
        app.mount("/dashboard", StaticFiles(directory=str(_DASHBOARD_DIST), html=True),
                  name="dashboard")

    return app
