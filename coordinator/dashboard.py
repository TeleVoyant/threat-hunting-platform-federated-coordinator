# coordinator/dashboard.py
"""
Operator web console for the FL coordinator.

A self-contained dashboard (Jinja2 + Alpine.js, no build step) that lets an FL
operator run every task from the browser — enroll/block/revoke orgs, start
rounds, aggregate, publish, roll back global models, and read the hash-chained
audit trail — WITHOUT typing a single curl command.

Design: the pages are a thin shell. Their Alpine `fetch` calls hit the existing
`/fl/*` JSON endpoints (coordinator/api.py), authenticated by the dashboard's
`fl_session` cookie (a coordinator-issued JWT). That means the dashboard reuses
the SAME RBAC and the SAME hash-chained audit logging as the programmatic API —
no duplicated business logic, and every mutation a click triggers is recorded in
the audit chain exactly as if it had been an API call.

Auth: login form posts {username, api_key}; the server validates against the FL
operator roster (FLAuthManager.authenticate_api_key), issues a JWT, and stores it
in an HttpOnly + SameSite=Lax cookie. Login and logout are themselves audited.
"""

from typing import Optional

from fastapi import APIRouter, Cookie, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from coordinator.security import FLAuthManager, FLUser, FL_PERMISSIONS

router = APIRouter(tags=["dashboard"])

COOKIE_NAME = "fl_session"


# ── Cookie auth helpers ─────────────────────────────────────────────────────

def current_user_from_cookie(request: Request, token: Optional[str]) -> Optional[FLUser]:
    if not token:
        return None
    am: FLAuthManager = request.app.state.fl_auth_manager
    return am.verify_jwt(token)


def require_user(
    request: Request,
    fl_session: Optional[str] = Cookie(default=None),
) -> FLUser:
    """Page guard — 303-redirect to the login page when not authenticated."""
    user = current_user_from_cookie(request, fl_session)
    if not user:
        raise HTTPException(status_code=303, headers={"Location": "/login"},
                            detail="Not authenticated")
    return user


def _perms(user: FLUser) -> dict:
    """Permission flags for template button-gating (server-side, not just cosmetic —
    the /fl/* endpoints re-check)."""
    have = FL_PERMISSIONS.get(user.role, set())
    return {p: (p in have) for p in (
        "fl_enroll_org", "fl_block_org", "fl_revoke_org",
        "fl_start_round", "fl_aggregate_round", "fl_view_audit",
    )}


def _ctx(request: Request, user: FLUser, active: str, **extra) -> dict:
    return {"user": {"username": user.username, "role": user.role.value},
            "perms": _perms(user), "active": active, **extra}


def _page(request: Request, name: str, user: FLUser, active: str, **extra):
    return request.app.state.templates.TemplateResponse(
        request, name, _ctx(request, user, active, **extra))


# ── Auth routes ─────────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: Optional[str] = None):
    return request.app.state.templates.TemplateResponse(
        request, "login.html", {"error": error})


@router.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    api_key:  str = Form(...),
):
    am: FLAuthManager = request.app.state.fl_auth_manager
    user = am.authenticate_api_key(api_key)
    if not user or user.username != username:
        return RedirectResponse("/login?error=Invalid+credentials", status_code=303)

    token = am.create_jwt(user, expires_hours=8)
    request.app.state.fl_audit_trail.log(
        action="fl.operator.login", actor=user.username,
        target=user.role.value, details={},
    )
    resp = RedirectResponse("/dashboard", status_code=303)
    resp.set_cookie(
        key=COOKIE_NAME, value=token,
        httponly=True,
        secure=False,        # set True behind HTTPS in production
        samesite="lax",
        max_age=8 * 3600,
        path="/",
    )
    return resp


@router.post("/logout")
async def logout(request: Request, fl_session: Optional[str] = Cookie(default=None)):
    user = current_user_from_cookie(request, fl_session)
    if user:
        request.app.state.fl_audit_trail.log(
            action="fl.operator.logout", actor=user.username, target="", details={})
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


# ── Page routes (render the shell; data loads via Alpine fetch to /fl/*) ─────

@router.get("/dashboard", response_class=HTMLResponse)
async def home(request: Request):
    user = require_user(request, request.cookies.get(COOKIE_NAME))
    return _page(request, "home.html", user, "home")


@router.get("/dashboard/orgs", response_class=HTMLResponse)
async def orgs(request: Request):
    user = require_user(request, request.cookies.get(COOKIE_NAME))
    return _page(request, "orgs.html", user, "orgs")


@router.get("/dashboard/rounds", response_class=HTMLResponse)
async def rounds(request: Request):
    user = require_user(request, request.cookies.get(COOKIE_NAME))
    return _page(request, "rounds.html", user, "rounds")


@router.get("/dashboard/rounds/{round_id}", response_class=HTMLResponse)
async def round_detail(request: Request, round_id: int):
    user = require_user(request, request.cookies.get(COOKIE_NAME))
    return _page(request, "round_detail.html", user, "rounds", round_id=round_id)


@router.get("/dashboard/models", response_class=HTMLResponse)
async def models(request: Request):
    user = require_user(request, request.cookies.get(COOKIE_NAME))
    return _page(request, "models.html", user, "models")


@router.get("/dashboard/audit", response_class=HTMLResponse)
async def audit(request: Request):
    user = require_user(request, request.cookies.get(COOKIE_NAME))
    return _page(request, "audit.html", user, "audit")
