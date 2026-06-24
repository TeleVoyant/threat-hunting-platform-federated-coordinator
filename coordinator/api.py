# federated/coordinator_api.py
"""
FL Coordinator REST management API.

This is INTENTIONALLY a separate FastAPI app from the org platform's
api/main.py. Mounted by federated/coordinator_app.py on its own port
(default 8889) and listens for FL operators only — never for org admins.

Auth: federated.fl_security.FLAuthManager — separate JWT secret + user
roster. See fl_security.py for the trust-boundary rationale.

Routes
------
  POST  /fl/orgs/enroll              FLAdmin       — add an organization
  GET   /fl/orgs                     FLViewer+     — list orgs + trust scores
  POST  /fl/orgs/{org_id}/block      FLOperator+   — block org from rounds
  POST  /fl/orgs/{org_id}/unblock    FLOperator+
  DELETE /fl/orgs/{org_id}           FLAdmin       — permanently revoke

  POST  /fl/rounds/start             FLOperator+   — start a new FL round
  GET   /fl/rounds                   FLViewer+     — list rounds
  GET   /fl/rounds/{round_id}        FLViewer+     — round detail + metrics

  GET   /fl/audit                    FLViewer+ (with fl_view_audit)

Every mutation is recorded in the coordinator's OWN AuditTrail (separate
SQLite from the org platform).
"""

import hashlib
import time
from typing import Optional

from fastapi import (
    APIRouter, Cookie, Depends, File, Form, Header, HTTPException, Request, UploadFile,
)
from fastapi.security import APIKeyHeader, HTTPBearer
from pydantic import BaseModel, Field

from flproto.attestation import (
    build_global_model_attestation, build_removal_confirm_attestation,
    build_round_announcement_attestation,
    build_trust_notification_attestation, generate_challenge,
    public_key_from_pem, public_key_to_pem, sign as att_sign, verify as att_verify,
)
from flproto.ca import (
    build_crl, cert_to_pem, issue_client_cert, CRL_FILE,
)
from cryptography.hazmat.primitives import serialization
from coordinator.aggregation import (
    describe_schema, merge_xgboost_models, model_feature_schema,
)
from coordinator.security import FLAuthManager, FLUser, generate_fl_api_key
from coordinator.logging import get_logger

logger = get_logger("coordinator.api")

router = APIRouter(prefix="/fl", tags=["fl-coordinator"])

# Reject oversized uploads up front (DoS / memory-exhaustion guard, SR-06).
# Override via FL_MAX_MODEL_BYTES. 64 MiB comfortably fits a 500-tree ensemble.
import os as _os
_MAX_MODEL_BYTES = int(_os.environ.get("FL_MAX_MODEL_BYTES", 64 * 1024 * 1024))


def _require_mtls() -> bool:
    """When FL_REQUIRE_MTLS is truthy the X-FL-API-Key org fallback is refused
    and org endpoints accept verified-mTLS identity ONLY. Set it in production
    (behind uvicorn --ssl-cert-reqs 2) so a misconfigured transport cannot
    silently downgrade to bootstrap-key auth. Read per-request so it can be
    toggled without rebuilding the app."""
    return _os.environ.get("FL_REQUIRE_MTLS", "0").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _default_observation_hours() -> float:
    """Default soak window (hours) for both the round intake window and the
    staged-global-model observation window. Set FL_OBSERVATION_HOURS=0 to make
    both immediate (useful for demos/tests)."""
    try:
        return float(_os.environ.get("FL_OBSERVATION_HOURS", "48"))
    except ValueError:
        return 48.0

_bearer  = HTTPBearer(auto_error=False)
_api_key = APIKeyHeader(name="X-FL-API-Key", auto_error=False)


# ── Auth dependencies (separate from api/middleware.py — different boundary) ─

async def get_fl_user(
    request: Request,
    bearer  = Depends(_bearer),
    api_key = Depends(_api_key),
    fl_session: Optional[str] = Cookie(default=None),
) -> FLUser:
    """Operator identity from (in order) a Bearer JWT, the dashboard's
    `fl_session` cookie JWT, or the X-FL-API-Key header. The cookie path lets
    the browser dashboard reuse these exact endpoints (same RBAC + audit)."""
    auth_manager: FLAuthManager = request.app.state.fl_auth_manager
    if bearer and bearer.credentials:
        user = auth_manager.verify_jwt(bearer.credentials)
        if user:
            return user
    if fl_session:
        user = auth_manager.verify_jwt(fl_session)
        if user:
            return user
    if api_key:
        user = auth_manager.authenticate_api_key(api_key)
        if user:
            return user
    raise HTTPException(401, "FL coordinator credentials required")


def fl_require(permission: str):
    async def check(
        request: Request,
        user: FLUser = Depends(get_fl_user),
    ) -> FLUser:
        am: FLAuthManager = request.app.state.fl_auth_manager
        if not am.has_permission(user, permission):
            raise HTTPException(
                403,
                f"Permission '{permission}' required (your FL role: {user.role.value})",
            )
        return user
    return check


def _store(request: Request):
    return request.app.state.coordinator_store


def _audit(request: Request):
    return request.app.state.fl_audit_trail


def _regenerate_crl(request: Request) -> bool:
    """Rebuild + persist the CRL from every revoked org's cert serial, then
    hot-reload it into app.state so mtls_middleware revocation checks see it
    immediately. Best-effort defense-in-depth: a revoked org is authoritatively
    blocked by its status!='active' check (both the api-key and mTLS paths), so a
    CRL write failure is logged but never fails the caller. No-op when the CA
    isn't initialised. Returns True on success."""
    ca_priv = getattr(request.app.state, "fl_ca_priv", None)
    ca_cert = getattr(request.app.state, "fl_ca_cert", None)
    if ca_priv is None or ca_cert is None:
        return False
    try:
        serials = _store(request).list_revoked_serials()
        crl = build_crl(ca_priv, ca_cert, revoked_serials=serials)
        ca_dir = _os.environ.get("FL_CA_DIR", "data/ca")
        from pathlib import Path as _Path
        (_Path(ca_dir) / CRL_FILE).write_bytes(crl.public_bytes(serialization.Encoding.PEM))
        request.app.state.fl_crl = crl
        return True
    except Exception as e:
        logger.warning("CRL regeneration failed; revoked org still blocked by "
                       "status check", error=str(e))
        return False


# ── Org authentication (mTLS preferred; API key fallback for bootstrap/test) ─

def _org_id_from_mtls_cert(request: Request) -> Optional[str]:
    """
    Extract org_id from the client cert presented during mTLS handshake.

    uvicorn (when run with --ssl-cert-reqs 2) populates the ASGI scope's
    'extensions' with 'transport' info and the underlying SSL object has
    .getpeercert(). The coordinator middleware (mtls_middleware) parses
    this once per request and attaches the verified org_id to scope.
    """
    return getattr(request.state, "mtls_org_id", None)


async def get_authenticated_org_id(
    request: Request,
    api_key = Depends(_api_key),
) -> str:
    """
    Identify the org for /fl/rounds/* endpoints.

      Production: mTLS — org_id from the verified client cert's CN
      Bootstrap / non-TLS test: X-FL-API-Key header matched against the
                                stored api_key_hash for an active org

    Returns the authenticated org_id. Raises 401 on any failure.
    """
    # Prefer mTLS identity (set by mtls_middleware once cert is verified)
    org_id = _org_id_from_mtls_cert(request)
    if org_id:
        return org_id

    # Production hardening: refuse the bootstrap api-key fallback when mTLS is
    # required, so org endpoints can only be reached with a verified client cert.
    if _require_mtls():
        raise HTTPException(
            401,
            "mTLS client certificate required (FL_REQUIRE_MTLS enabled); "
            "the X-FL-API-Key bootstrap fallback is disabled",
        )

    # Fallback to API-key bootstrap auth (constant-time compare; hash once).
    if api_key:
        import hmac as _hmac
        api_hash = hashlib.sha256(api_key.encode()).hexdigest()
        for org in _store(request).list_orgs():
            if org["status"] != "active":
                continue
            if _hmac.compare_digest(org["api_key_hash"], api_hash):
                return org["org_id"]

    raise HTTPException(
        401,
        "Org authentication required (mTLS client cert or X-FL-API-Key header)",
    )


# ── Request models ──────────────────────────────────────────────────────────

class EnrollOrgRequest(BaseModel):
    org_id:         str           = Field(..., min_length=1, max_length=64,
                                          pattern=r"^[a-zA-Z0-9_-]+$")
    display_name:   str           = Field(..., min_length=1, max_length=128)
    public_key_pem: str           = Field(...,
        description="PEM-encoded Ed25519 public key the org generated locally. "
                    "Coordinator wraps this in a CA-signed client cert."
    )
    notes:          Optional[str] = None


class StartRoundRequest(BaseModel):
    epsilon:           float = Field(1.0, gt=0.0, le=10.0,
                                     description="Differential privacy budget (lower = more private)")
    num_boost_rounds:  int   = Field(10, ge=1, le=200,
                                     description="Local boost rounds per client per FL round")
    min_clients:       int   = Field(2, ge=1, le=100)
    target_org_ids:    Optional[list[str]] = Field(
        None,
        description="If null, invite all active orgs. Otherwise restrict to this list.",
    )
    observation_hours: Optional[float] = Field(
        None, ge=0.0, le=720.0,
        description="Intake + staged-model observation window (hours). Defaults "
                    "to FL_OBSERVATION_HOURS (48). 0 = no wait (demo/test).",
    )


# ── Org enrollment / lifecycle ─────────────────────────────────────────────

@router.post("/orgs/enroll", status_code=201)
async def enroll_org(
    body: EnrollOrgRequest,
    request: Request,
    user: FLUser = Depends(fl_require("fl_enroll_org")),
):
    """
    Add a new participating organization with both layers of identity:

      1. Ed25519 public key (provided by the org) registered + wrapped in a
         CA-signed client cert that the org will use for mTLS handshake.
      2. One-time API key for bootstrap authentication BEFORE the org has
         the cert installed.

    Response includes the issued client cert + the federation CA cert + the
    coordinator's public key, all of which the org imports during /fl/local/configure.
    """
    store = _store(request)

    # ── Validate the supplied public key ────────────────────────────────────
    try:
        org_pub = public_key_from_pem(body.public_key_pem.encode())
    except Exception as e:
        raise HTTPException(
            400,
            f"Invalid public_key_pem (must be Ed25519 SubjectPublicKeyInfo PEM): {e}",
        )

    # ── Issue a CA-signed client cert ───────────────────────────────────────
    ca_priv  = request.app.state.fl_ca_priv
    ca_cert  = request.app.state.fl_ca_cert
    if ca_priv is None or ca_cert is None:
        raise HTTPException(
            503,
            "Federation CA not initialised — run `python -m federated.init_fl_ca` first.",
        )
    client_cert = issue_client_cert(
        ca_priv=ca_priv, ca_cert=ca_cert,
        client_pub=org_pub,
        org_id=body.org_id, display_name=body.display_name,
    )
    client_cert_pem = cert_to_pem(client_cert).decode()
    cert_serial = str(client_cert.serial_number)

    api_key, api_key_hash = generate_fl_api_key()
    try:
        store.enroll_org(
            org_id=body.org_id, display_name=body.display_name,
            api_key_hash=api_key_hash, enrolled_by=user.username,
            public_key_pem=body.public_key_pem,
            cert_pem=client_cert_pem,
            cert_serial=cert_serial,
            notes=body.notes,
        )
    except ValueError as e:
        raise HTTPException(409, str(e))

    _audit(request).log(
        action="fl.org.enroll",
        actor=user.username,
        target=body.org_id,
        details={
            "display_name": body.display_name,
            "cert_serial":  cert_serial,
            "pub_key_sha256": hashlib.sha256(
                body.public_key_pem.encode()
            ).hexdigest()[:16],
        },
    )

    coord_pub_pem = public_key_to_pem(
        request.app.state.fl_coord_priv.public_key()
    ).decode()

    return {
        "org_id":              body.org_id,
        "api_key":             api_key,
        "client_cert_pem":     client_cert_pem,     # use for mTLS handshake
        "ca_cert_pem":         cert_to_pem(ca_cert).decode(),  # trust anchor
        "coordinator_pub_pem": coord_pub_pem,        # verify coord-signed responses
        "cert_serial":         cert_serial,
        "warning":             "Store the api_key and the org's PRIVATE key "
                                "securely. The api_key cannot be retrieved again "
                                "and is intended for bootstrap only — switch to "
                                "mTLS for all subsequent calls.",
    }


@router.get("/orgs")
async def list_orgs(
    request: Request,
    user: FLUser = Depends(fl_require("fl_view_orgs")),
):
    """List every enrolled org with current status + trust score."""
    orgs = _store(request).list_orgs()
    # Strip the api_key_hash from the response — operators don't need it
    for o in orgs:
        o.pop("api_key_hash", None)
    return {"orgs": orgs}


@router.post("/orgs/{org_id}/block")
async def block_org(
    org_id: str,
    request: Request,
    user: FLUser = Depends(fl_require("fl_block_org")),
):
    """
    Block an org from participating in future rounds. Useful when the
    trust manager flags repeated bad contributions.
    """
    store = _store(request)
    if not store.get_org(org_id):
        raise HTTPException(404, f"Unknown org: {org_id}")
    store.set_org_status(org_id, "blocked")
    _audit(request).log("fl.org.block", user.username, org_id, {})
    return {"org_id": org_id, "status": "blocked"}


@router.post("/orgs/{org_id}/unblock")
async def unblock_org(
    org_id: str,
    request: Request,
    user: FLUser = Depends(fl_require("fl_unblock_org")),
):
    store = _store(request)
    if not store.get_org(org_id):
        raise HTTPException(404, f"Unknown org: {org_id}")
    store.set_org_status(org_id, "active")
    _audit(request).log("fl.org.unblock", user.username, org_id, {})
    return {"org_id": org_id, "status": "active"}


@router.delete("/orgs/{org_id}")
async def revoke_org(
    org_id: str,
    request: Request,
    user: FLUser = Depends(fl_require("fl_revoke_org")),
):
    """Permanently revoke an org's enrollment. API key becomes invalid."""
    store = _store(request)
    if not store.get_org(org_id):
        raise HTTPException(404, f"Unknown org: {org_id}")
    store.set_org_status(org_id, "revoked")
    _regenerate_crl(request)
    _audit(request).log("fl.org.revoke", user.username, org_id, {})
    return {"org_id": org_id, "status": "revoked"}


# ── Mutual-ack org removal (org self-removal handshake) ─────────────────────

class LeaveRequestBody(BaseModel):
    attestation: str = Field(..., description="canonical-JSON bytes (utf-8) of the org-signed fl.leave_request.v1")
    signature:   str = Field(..., description="hex Ed25519 signature over attestation")


@router.post("/orgs/{org_id}/leave-request")
async def org_leave_request(
    org_id: str,
    body: LeaveRequestBody,
    request: Request,
    auth_org_id: str = Depends(get_authenticated_org_id),
):
    """Org-initiated half of the mutual-ack removal. The org submits a SIGNED
    fl.leave_request.v1; the coordinator verifies it against the org's public
    key, moves the org to 'leave_pending' (no longer invited to rounds), and
    stores the signed request. Completion still requires operator approval."""
    store = _store(request)
    if auth_org_id != org_id:
        raise HTTPException(403, "authenticated org does not match path org_id")
    org = store.get_org(org_id)
    if not org:
        raise HTTPException(404, f"Unknown org: {org_id}")
    if org["status"] == "revoked":
        raise HTTPException(409, "org already removed")
    att_bytes = body.attestation.encode("utf-8")
    import json as _json
    try:
        att = _json.loads(att_bytes)
    except Exception:
        raise HTTPException(400, "attestation is not valid JSON")
    if att.get("type") != "fl.leave_request.v1" or att.get("org_id") != org_id:
        raise HTTPException(400, "attestation type/org_id mismatch")
    pub_pem = org.get("public_key_pem")
    if not pub_pem:
        raise HTTPException(403, "Org has no public key registered")
    try:
        sig_bytes = bytes.fromhex(body.signature)
    except ValueError:
        raise HTTPException(400, "signature must be hex-encoded")
    if not att_verify(public_key_from_pem(pub_pem.encode()), att_bytes, sig_bytes):
        raise HTTPException(403, "leave-request signature verification failed")
    store.set_leave_request(org_id, att_bytes, body.signature)
    _audit(request).log(
        action="fl.org.leave_requested", actor=f"org:{org_id}", target=org_id,
        details={"reason": str(att.get("reason", ""))[:200]},
    )
    return {"org_id": org_id, "status": "leave_pending",
            "note": "awaiting operator approval (POST /fl/orgs/{org_id}/approve-removal)"}


@router.post("/orgs/{org_id}/approve-removal")
async def approve_removal(
    org_id: str,
    request: Request,
    user: FLUser = Depends(fl_require("fl_revoke_org")),
):
    """Operator half of the mutual-ack removal: ONLY valid when the org has a
    pending leave request (status 'leave_pending'). Revokes the org, regenerates
    the CRL, and emits a coordinator-SIGNED fl.removal_confirm.v1 the org
    verifies before wiping locally. Force-removing a non-requesting org uses
    DELETE /orgs/{id} instead."""
    store = _store(request)
    org = store.get_org(org_id)
    if not org:
        raise HTTPException(404, f"Unknown org: {org_id}")
    if org["status"] != "leave_pending":
        raise HTTPException(
            409,
            f"org has not requested to leave (status={org['status']}). "
            f"Use DELETE /fl/orgs/{org_id} to force-revoke.",
        )
    coord_priv = getattr(request.app.state, "fl_coord_priv", None)
    if coord_priv is None:
        raise HTTPException(503, "Coordinator signing key not loaded")
    # Sign + persist the removal confirmation FIRST so the org can always
    # finalize, even if the best-effort CRL regen below fails.
    confirm_bytes = build_removal_confirm_attestation(org_id=org_id)
    sig_hex = att_sign(coord_priv, confirm_bytes).hex()
    store.set_org_status(org_id, "revoked")
    store.set_removal_confirm(org_id, confirm_bytes, sig_hex)
    _regenerate_crl(request)
    _audit(request).log(
        action="fl.org.removal_approved", actor=user.username, target=org_id, details={},
    )
    return {
        "org_id": org_id, "status": "revoked",
        "removal_confirm": {"signed_attestation": confirm_bytes.decode("utf-8"),
                            "signature_hex": sig_hex},
    }


@router.get("/orgs/{org_id}/removal-status")
async def removal_status(
    org_id: str,
    request: Request,
    api_key = Depends(_api_key),
):
    """Org polls this to learn whether its removal was approved and to fetch the
    coordinator-signed confirmation. Auth is relaxed so a leave_pending OR
    revoked org can read its OWN status (standard org-auth requires 'active',
    which a just-revoked org no longer is). Read-only, own org only."""
    store = _store(request)
    org = store.get_org(org_id)
    if not org:
        raise HTTPException(404, f"Unknown org: {org_id}")
    auth_ok = getattr(request.state, "mtls_org_id", None) == org_id
    if not auth_ok and api_key:
        import hmac as _hmac
        h = hashlib.sha256(api_key.encode()).hexdigest()
        auth_ok = _hmac.compare_digest(org["api_key_hash"], h)
    if not auth_ok:
        raise HTTPException(401, "auth required (mTLS client cert or X-FL-API-Key for this org)")
    resp = {"org_id": org_id, "status": org["status"]}
    ra = org.get("removal_attestation")
    if org["status"] == "revoked" and ra:
        resp["removal_confirm"] = {
            "signed_attestation": ra.decode("utf-8") if isinstance(ra, (bytes, bytearray)) else ra,
            "signature_hex": org.get("removal_signature"),
        }
    return resp


# ── Rounds ─────────────────────────────────────────────────────────────────

@router.post("/rounds/start", status_code=202)
async def start_round(
    body: StartRoundRequest,
    request: Request,
    user: FLUser = Depends(fl_require("fl_start_round")),
):
    """
    Open a new FL round: validate the invited set, record the round, and —
    when the federation CA is initialised — emit a coordinator-SIGNED round
    announcement so invited orgs can cryptographically verify the round is
    authentic before training/contributing (fetched via
    GET /rounds/{id}/announcement). Aggregation happens later over REST via
    POST /rounds/{id}/aggregate; there is no Flower/gRPC server involved.
    """
    store = _store(request)
    active_orgs = [o for o in store.list_orgs() if o["status"] == "active"]
    if body.target_org_ids:
        invited = [o for o in active_orgs if o["org_id"] in body.target_org_ids]
    else:
        invited = active_orgs
    if len(invited) < body.min_clients:
        raise HTTPException(
            422,
            f"Only {len(invited)} active orgs but min_clients={body.min_clients}",
        )
    invited_ids = [o["org_id"] for o in invited]

    obs_hours = (body.observation_hours if body.observation_hours is not None
                 else _default_observation_hours())
    params = body.model_dump()
    params["observation_hours"] = obs_hours

    round_id = store.start_round(
        started_by=user.username,
        params=params,
        invited_count=len(invited),
    )
    intake_until = store.get_round(round_id)["started_at"] + obs_hours * 3600

    # Coordinator-signed round announcement (no rogue round invites). Requires
    # the coordinator keypair; skipped gracefully when the CA is not loaded.
    announcement = None
    coord_priv = getattr(request.app.state, "fl_coord_priv", None)
    if coord_priv is not None:
        ann_bytes = build_round_announcement_attestation(
            round_id=round_id,
            epsilon=body.epsilon,
            num_boost_rounds=body.num_boost_rounds,
            invited_org_ids=invited_ids,
        )
        sig_hex = att_sign(coord_priv, ann_bytes).hex()
        store.set_round_announcement(round_id, ann_bytes, sig_hex)
        announcement = {
            "signed_attestation": ann_bytes.decode("utf-8"),
            "signature_hex": sig_hex,
        }

    _audit(request).log(
        action="fl.round.start",
        actor=user.username,
        target=f"round_{round_id}",
        details={
            "epsilon":         body.epsilon,
            "num_boost_rounds": body.num_boost_rounds,
            "invited_orgs":    invited_ids,
            "announced":       announcement is not None,
        },
    )
    return {
        "round_id":           round_id,
        "status":             "running",
        "invited_orgs":       invited_ids,
        "params":             params,
        "observation_hours":  obs_hours,
        "intake_until":       intake_until,
        "round_announcement": announcement,
    }


@router.get("/rounds")
async def list_rounds(
    request: Request,
    limit: int = 50,
    user: FLUser = Depends(fl_require("fl_view_rounds")),
):
    return {"rounds": _store(request).list_rounds(limit=limit)}


# Declared BEFORE /rounds/{round_id} so the literal path wins over the int param.
@router.get("/rounds/active")
async def list_active_rounds_for_org(
    request: Request,
    org_id: str = Depends(get_authenticated_org_id),
):
    """Org-facing round discovery: open rounds (status 'running') this org is
    invited to, so a participant client can find and join rounds without
    out-of-band coordination. Each entry says whether the intake window is still
    open (contributions accepted) or has closed (awaiting aggregation)."""
    store = _store(request)
    now = time.time()
    out = []
    for r in store.list_rounds_by_status("running"):
        params = r.get("params") or {}
        targets = params.get("target_org_ids")
        if targets and org_id not in targets:
            continue
        obs_hours = float(params.get("observation_hours", 0) or 0)
        intake_until = r["started_at"] + obs_hours * 3600
        out.append({
            "round_id":         r["round_id"],
            "started_at":       r["started_at"],
            "intake_until":     intake_until,
            "intake_open":      now < intake_until,
            "epsilon":          params.get("epsilon"),
            "num_boost_rounds": params.get("num_boost_rounds"),
        })
    return {"org_id": org_id, "active_rounds": out}


@router.get("/rounds/{round_id}")
async def get_round(
    round_id: int,
    request: Request,
    user: FLUser = Depends(fl_require("fl_view_rounds")),
):
    r = _store(request).get_round(round_id)
    if not r:
        raise HTTPException(404, f"Round not found: {round_id}")
    return r


# ── Org-facing round endpoints (mTLS auth) ─────────────────────────────────

@router.get("/rounds/{round_id}/challenge")
async def issue_round_challenge(
    round_id: int,
    request: Request,
    org_id: str = Depends(get_authenticated_org_id),
):
    """
    One-shot nonce for an org's upcoming contribution to this round.
    Bound to (org_id, round_id), expires in 10 minutes, consumed atomically
    when the contribution is submitted.
    """
    store = _store(request)
    r = store.get_round(round_id)
    if not r:
        raise HTTPException(404, f"Round not found: {round_id}")
    if r["status"] != "running":
        raise HTTPException(409, f"Round {round_id} is not running ({r['status']})")
    if not store.get_org(org_id):
        raise HTTPException(403, "Unknown org")

    challenge = generate_challenge()
    info = store.issue_challenge(org_id, round_id, challenge, ttl_seconds=600)
    return {"challenge": info["challenge"], "expires_at": info["expires_at"]}


@router.get("/rounds/{round_id}/announcement")
async def get_round_announcement(
    round_id: int,
    request: Request,
    org_id: str = Depends(get_authenticated_org_id),
):
    """
    Coordinator-signed announcement for this round. An invited org verifies the
    Ed25519 signature with the coordinator public key it received at enrollment,
    confirming the round (id, epsilon, boost rounds, invited set) was authorised
    by the coordinator before it trains or contributes — defends against rogue
    round invites from a coordinator-impersonator.
    """
    r = _store(request).get_round(round_id)
    if not r:
        raise HTTPException(404, f"Round not found: {round_id}")
    ann = r.get("round_announcement")
    if not ann:
        raise HTTPException(404, f"Round {round_id} has no signed announcement")
    return {"round_id": round_id, **ann}


@router.post("/rounds/{round_id}/contribute", status_code=202)
async def submit_contribution(
    round_id: int,
    request: Request,
    attestation: str  = Form(..., description="Canonical-JSON bytes that were signed (UTF-8 string)"),
    signature:   str  = Form(..., description="Hex-encoded Ed25519 signature over attestation"),
    model:       UploadFile = File(..., description="The XGBoost model bytes"),
    org_id: str = Depends(get_authenticated_org_id),
):
    """
    Verify + record one org's contribution. The verification chain:
      1. Parse attestation → must be valid canonical JSON
      2. attestation.org_id must match authenticated org
      3. attestation.round_id must match URL
      4. Compute SHA-256 of uploaded model — must equal attestation.model_sha256
      5. attestation.submitted_at within ±5 min of server clock
      6. Atomically consume attestation.challenge (rejects expired/replayed)
      7. Verify Ed25519 signature with the org's stored public key

    Only when ALL checks pass is the contribution recorded as `accepted=1`
    and forwarded to the trust manager (in the demo runner).
    """
    import json
    store = _store(request)

    # ── 1. Parse attestation ─────────────────────────────────────────────────
    att_bytes = attestation.encode("utf-8")
    try:
        att = json.loads(att_bytes)
    except json.JSONDecodeError as e:
        raise HTTPException(400, f"attestation is not valid JSON: {e}")
    for required in ("type", "round_id", "org_id", "model_sha256",
                      "num_examples", "challenge", "submitted_at"):
        if required not in att:
            raise HTTPException(400, f"attestation missing field: {required}")
    if att["type"] != "fl.contribution.v1":
        raise HTTPException(400, f"Unexpected attestation type: {att['type']}")

    # ── 2. org_id binding ────────────────────────────────────────────────────
    if att["org_id"] != org_id:
        _store(request)  # to make linter happy
        raise HTTPException(403,
            f"attestation.org_id ({att['org_id']}) does not match "
            f"authenticated org ({org_id})")

    # ── 3. round_id binding ──────────────────────────────────────────────────
    if int(att["round_id"]) != round_id:
        raise HTTPException(403,
            f"attestation.round_id ({att['round_id']}) does not match URL ({round_id})")

    # ── 3b. Round must be running; one accepted contribution per (org, round) ─
    r = store.get_round(round_id)
    if not r:
        raise HTTPException(404, f"Round not found: {round_id}")
    if r["status"] != "running":
        raise HTTPException(409, f"Round {round_id} is not running ({r['status']})")
    if store.has_accepted_contribution(round_id, org_id):
        raise HTTPException(409,
            "Org already has an accepted contribution for this round")

    # ── 4. model bytes integrity (+ size guard, SR-06) ───────────────────────
    model_bytes = await model.read()
    if len(model_bytes) > _MAX_MODEL_BYTES:
        raise HTTPException(413,
            f"model exceeds FL_MAX_MODEL_BYTES ({_MAX_MODEL_BYTES} bytes)")
    actual_hash = hashlib.sha256(model_bytes).hexdigest()
    if actual_hash != att["model_sha256"]:
        raise HTTPException(400,
            f"model_sha256 mismatch (expected {att['model_sha256'][:16]}…, "
            f"got {actual_hash[:16]}…)")

    # ── 5. submitted_at freshness ────────────────────────────────────────────
    from datetime import datetime, timezone
    try:
        sent = datetime.fromisoformat(att["submitted_at"].replace("Z", "+00:00"))
    except Exception:
        raise HTTPException(400, "attestation.submitted_at is not valid ISO 8601")
    if sent.tzinfo is None:
        sent = sent.replace(tzinfo=timezone.utc)
    drift = abs((datetime.now(timezone.utc) - sent).total_seconds())
    if drift > 300:
        raise HTTPException(400, f"attestation timestamp drift {drift:.0f}s > 300s")

    # ── 6. Consume challenge (atomic — replay-safe) ──────────────────────────
    err = store.consume_challenge(att["challenge"], org_id, round_id)
    if err:
        raise HTTPException(403, f"Challenge rejected: {err}")

    # ── 7. Verify signature ─────────────────────────────────────────────────
    pub_pem = store.get_org_public_key(org_id)
    if not pub_pem:
        raise HTTPException(403, "Org has no public key registered")
    pub = public_key_from_pem(pub_pem.encode())
    try:
        sig_bytes = bytes.fromhex(signature)
    except ValueError:
        raise HTTPException(400, "signature must be hex-encoded")
    if not att_verify(pub, att_bytes, sig_bytes):
        # Record the rejection so audit shows the attempt
        store.record_contribution(
            round_id=round_id, org_id=org_id,
            model_sha256=actual_hash, num_examples=int(att["num_examples"]),
            signed_attestation=att_bytes, signature_hex=signature,
            challenge=att["challenge"], accepted=False,
            rejection_reason="signature verification failed",
        )
        _audit(request).log(
            action="fl.contribution.signature_invalid",
            actor=f"org:{org_id}",
            target=f"round_{round_id}",
            details={"model_sha256": actual_hash[:16]},
        )
        raise HTTPException(403, "Signature verification failed")

    # ── All checks passed — persist model bytes + record + return ────────────
    from pathlib import Path as _Path
    round_dir = _Path(request.app.state.fl_model_dir) / f"round_{round_id}"
    round_dir.mkdir(parents=True, exist_ok=True)
    model_path = str(round_dir / f"contrib_{org_id}_{actual_hash[:16]}.json")
    _Path(model_path).write_bytes(model_bytes)
    cid = store.record_contribution(
        round_id=round_id, org_id=org_id,
        model_sha256=actual_hash, num_examples=int(att["num_examples"]),
        signed_attestation=att_bytes, signature_hex=signature,
        challenge=att["challenge"], accepted=True, model_path=model_path,
    )
    _audit(request).log(
        action="fl.contribution.accepted",
        actor=f"org:{org_id}",
        target=f"round_{round_id}",
        details={
            "contribution_id": cid,
            "model_sha256":    actual_hash[:16],
            "num_examples":    int(att["num_examples"]),
        },
    )
    return {
        "contribution_id": cid,
        "accepted":        True,
        "round_id":        round_id,
        "org_id":          org_id,
        "model_sha256":    actual_hash,
    }


def _signed_model_response(request: Request, round_id: int, model_bytes: bytes) -> dict:
    """Coordinator-sign `model_bytes` for `round_id` and shape the org response.
    signed_attestation is the EXACT bytes the coordinator signed — the org
    verifies against these (do NOT re-canonicalise)."""
    import base64
    store = _store(request)
    accepted_orgs = [
        c["org_id"] for c in store.list_contributions(round_id=round_id) if c["accepted"]
    ]
    att_bytes = build_global_model_attestation(
        round_id=round_id, model_bytes=model_bytes,
        accepted_org_ids=sorted(set(accepted_orgs)),
    )
    sig = att_sign(request.app.state.fl_coord_priv, att_bytes)
    return {
        "round_id":           round_id,
        "model_b64":          base64.b64encode(model_bytes).decode(),
        "signed_attestation": att_bytes.decode("utf-8"),
        "signature_hex":      sig.hex(),
    }


@router.get("/global-model")
async def get_active_global_model(
    request: Request,
    org_id: str = Depends(get_authenticated_org_id),
):
    """The CURRENT published (active) global model, coordinator-signed. This is
    the endpoint orgs poll to pick up the latest model after a round is
    published. 404 until the first version has been published."""
    from pathlib import Path
    gm = _store(request).get_active_global_model()
    if not gm:
        raise HTTPException(404, "No global model has been published yet")
    p = Path(gm["model_path"])
    if not p.exists():
        raise HTTPException(404, "Active global model file missing on disk")
    resp = _signed_model_response(request, gm["round_id"], p.read_bytes())
    resp["version_id"] = gm["version_id"]
    resp["status"] = "active"
    return resp


@router.get("/rounds/{round_id}/global-model")
async def get_round_global_model(
    round_id: int,
    request: Request,
    org_id: str = Depends(get_authenticated_org_id),
):
    """The published global model produced from a SPECIFIC round (history). Only
    available once that round has been published (status 'completed'); a staged-
    but-not-yet-published round returns 409."""
    from pathlib import Path
    store = _store(request)
    r = store.get_round(round_id)
    if not r:
        raise HTTPException(404, f"Round not found: {round_id}")
    if r["status"] != "completed":
        raise HTTPException(
            409, f"Round {round_id} model not published yet (status {r['status']})")
    p = Path(request.app.state.fl_model_dir) / f"round_{round_id}.json"
    if not p.exists():
        raise HTTPException(404, f"Aggregated model file missing for round {round_id}")
    return _signed_model_response(request, round_id, p.read_bytes())


# ── Aggregation (combine accepted matrices into the global model) ───────────

@router.post("/rounds/{round_id}/aggregate")
async def aggregate_round(
    round_id: int,
    request: Request,
    user: FLUser = Depends(fl_require("fl_aggregate_round")),
):
    """
    Combine every accepted contribution for a round into one STAGED global model.

    Pipeline:
      1. Round must be 'running' AND past its intake/observation window.
      2. Load each accepted contribution's persisted model bytes.
      3. Trust-validate each (structure + public-validation accuracy + sudden-
         drop poisoning check); persist updated trust scores; EXCLUDE orgs
         below the trust floor (SR-05).
      4. Feature-schema gate: every matrix bagged into the global model MUST
         share one feature space (same feature_names / num_feature). Survivors
         whose schema differs from the heaviest survivor's are excluded — bagging
         misaligned feature spaces silently corrupts the global model.
      5. Federated-bagging merge of survivors, weighted by trust x num_examples.
      6. Persist round_{id}.json + record it as a STAGED global-model version that
         soaks under observation; round -> 'aggregated'. (completed_at unset.)

    The staged model is NOT served to orgs. The operator promotes it with
    POST /rounds/{round_id}/publish after the soak window, then it is served
    (coordinator-signed) by GET /global-model.
    """
    from pathlib import Path

    store = _store(request)
    r = store.get_round(round_id)
    if not r:
        raise HTTPException(404, f"Round not found: {round_id}")
    if r["status"] != "running":
        raise HTTPException(409, f"Round {round_id} is not running ({r['status']})")

    # Intake/observation window: contributions are collected + observed before
    # they can be combined. Refuse to aggregate until the window elapses.
    obs_hours = float((r.get("params") or {}).get("observation_hours", 0) or 0)
    remaining = (r["started_at"] + obs_hours * 3600) - time.time()
    if remaining > 0:
        raise HTTPException(
            409,
            f"Round {round_id} still in intake/observation for {int(remaining)}s "
            f"more (window {obs_hours}h); contributions are still being collected",
        )

    tm = getattr(request.app.state, "trust_manager", None)
    if tm is None:
        raise HTTPException(503, "Trust manager not initialised")

    accepted = store.get_accepted_models(round_id)
    if not accepted:
        raise HTTPException(422, "No accepted contributions to aggregate")

    coord_priv = request.app.state.fl_coord_priv
    survivors_raw: list[tuple[str, bytes, float]] = []   # (org_id, model_bytes, weight)
    results: list[dict] = []
    trust_updates: list[dict] = []
    for c in accepted:
        try:
            mb = Path(c["model_path"]).read_bytes()
        except OSError:
            results.append({"org_id": c["org_id"], "accepted": False,
                            "accuracy": None, "trust": c["trust_score"],
                            "reason": "model bytes missing on disk"})
            continue
        ev = tm.evaluate(c["org_id"], mb, c["num_examples"])
        results.append({"org_id": c["org_id"], "accepted": ev["accepted"],
                        "accuracy": ev["accuracy"], "trust": ev["trust"],
                        "reason": ev["reason"]})
        if ev["accepted"]:
            survivors_raw.append((c["org_id"], mb, ev["weight"]))
        # Signed, non-repudiable per-org trust-update notification.
        if coord_priv is not None:
            tu = build_trust_notification_attestation(
                org_id=c["org_id"], round_id=round_id,
                new_trust_score=ev["trust"], reason=ev["reason"])
            trust_updates.append({
                "org_id":             c["org_id"],
                "signed_attestation": tu.decode("utf-8"),
                "signature_hex":      att_sign(coord_priv, tu).hex(),
            })

    if not survivors_raw:
        # Everyone failed validation — leave the round running for the operator
        # to investigate. Trust changes have already been persisted.
        raise HTTPException(
            422,
            "All accepted contributions were rejected by trust validation; "
            "round left running",
        )

    # ── Feature-schema consistency gate (step 4) ─────────────────────────────
    # All bagged matrices must share one feature space. Canonical = the schema
    # of the heaviest survivor; any survivor that disagrees is demoted to
    # rejected so its tree splits never land in a misaligned global model.
    survivors_raw.sort(key=lambda t: t[2], reverse=True)
    canonical = model_feature_schema(survivors_raw[0][1])
    weighted: list[tuple[bytes, float]] = []
    excluded_schema: list[str] = []
    for oid, mb, w in survivors_raw:
        if model_feature_schema(mb) == canonical:
            weighted.append((mb, w))
        else:
            reason = (f"feature-schema mismatch (expected {describe_schema(canonical)}, "
                      f"got {describe_schema(model_feature_schema(mb))})")
            for x in results:
                if x["org_id"] == oid:
                    x["accepted"] = False
                    x["reason"] = reason
            excluded_schema.append(oid)
            logger.warning("contribution excluded — feature-schema mismatch",
                           org=oid, round_id=round_id,
                           expected=describe_schema(canonical))
    if excluded_schema:
        _audit(request).log(
            action="fl.round.schema_mismatch", actor=user.username,
            target=f"round_{round_id}",
            details={"canonical": describe_schema(canonical),
                     "excluded_orgs": excluded_schema},
        )

    global_bytes, info = merge_xgboost_models(weighted)
    model_dir = Path(request.app.state.fl_model_dir)
    (model_dir / f"round_{round_id}.json").write_bytes(global_bytes)
    global_hash = hashlib.sha256(global_bytes).hexdigest()

    survivors = [x["org_id"] for x in results if x["accepted"]]

    # Stage the merged model under observation. The operator publishes it after
    # the soak window via POST /rounds/{id}/publish; round -> 'aggregated'. The
    # model is NOT served to orgs until promoted to 'active'.
    staged_until = time.time() + obs_hours * 3600
    version_id = store.stage_global_model(
        round_id, model_hash=global_hash,
        model_path=str(model_dir / f"round_{round_id}.json"),
        staged_until=staged_until,
        eval_metrics={"merge": info, "contributors": results},
    )
    store.complete_round(
        round_id, status="aggregated",
        responded=len(accepted), accepted=len(survivors),
        rejected=len(accepted) - len(survivors),
        global_model_hash=global_hash,
        eval_metrics={"merge": info, "contributors": results},
    )
    _audit(request).log(
        action="fl.round.aggregated", actor=user.username,
        target=f"round_{round_id}",
        details={"version_id": version_id, "global_model_sha256": global_hash[:16],
                 "accepted": survivors, "total_trees": info["total_trees"]},
    )
    return {
        "round_id":            round_id,
        "status":              "aggregated",
        "version_id":          version_id,
        "global_model_sha256": global_hash,
        "accepted_orgs":       survivors,
        "rejected":            [x for x in results if not x["accepted"]],
        "merge":               info,
        "staged_until":        staged_until,
        "trust_updates":       trust_updates,
    }


# ── Global-model versioning: publish (promote staged) + rollback ────────────

@router.post("/rounds/{round_id}/publish")
async def publish_round_model(
    round_id: int,
    request: Request,
    user: FLUser = Depends(fl_require("fl_aggregate_round")),
):
    """
    Promote a round's STAGED global model to 'active' (published) after its soak
    window elapses, archiving the previously-active version. Only after this are
    orgs served the model (GET /global-model). Operator-triggered.
    """
    store = _store(request)
    r = store.get_round(round_id)
    if not r:
        raise HTTPException(404, f"Round not found: {round_id}")
    staged = store.get_staged_model_for_round(round_id)
    if not staged:
        raise HTTPException(409, f"Round {round_id} has no staged model — aggregate first")
    remaining = staged["staged_until"] - time.time()
    if remaining > 0:
        raise HTTPException(
            409,
            f"Staged model v{staged['version_id']} still under observation for "
            f"{int(remaining)}s more; publish refused until the soak window elapses",
        )
    gm = store.promote_global_model(staged["version_id"], user.username)
    store.set_round_status(round_id, "completed")
    _audit(request).log(
        action="fl.global_model.publish", actor=user.username,
        target=f"round_{round_id}",
        details={"version_id": gm["version_id"], "model_sha256": gm["model_hash"][:16]},
    )
    return {"version_id": gm["version_id"], "round_id": round_id,
            "status": "active", "model_sha256": gm["model_hash"],
            "promoted_at": gm["promoted_at"]}


@router.get("/models")
async def list_global_models(
    request: Request,
    limit: int = 50,
    user: FLUser = Depends(fl_require("fl_view_rounds")),
):
    """Version history of every global model: staged | active | archived."""
    return {"models": _store(request).list_global_models(limit=limit),
            "active": _store(request).get_active_global_model()}


@router.post("/models/{version_id}/rollback")
async def rollback_global_model(
    version_id: int,
    request: Request,
    user: FLUser = Depends(fl_require("fl_aggregate_round")),
):
    """
    Roll the published global model back to a previous version: make
    `version_id` active and archive the currently-active one. Refuses to
    activate a version still under observation (staged).
    """
    store = _store(request)
    target = store.get_global_model(version_id)
    if not target:
        raise HTTPException(404, f"Unknown global-model version: {version_id}")
    if target["status"] == "staged":
        raise HTTPException(
            409, f"Version {version_id} is still staged/under observation — "
                 "publish it normally rather than rolling back to it")
    gm = store.promote_global_model(version_id, user.username)
    _audit(request).log(
        action="fl.global_model.rollback", actor=user.username,
        target=f"version_{version_id}",
        details={"version_id": version_id, "round_id": gm["round_id"],
                 "model_sha256": gm["model_hash"][:16]},
    )
    return {"version_id": version_id, "round_id": gm["round_id"],
            "status": "active", "model_sha256": gm["model_hash"]}


# ── Audit ──────────────────────────────────────────────────────────────────

@router.get("/audit")
async def view_audit(
    request: Request,
    limit: int = 100,
    user: FLUser = Depends(fl_require("fl_view_audit")),
):
    """FL coordinator audit trail. Separate from org platform's audit DB."""
    return {"entries": _audit(request).query(limit=limit)}
