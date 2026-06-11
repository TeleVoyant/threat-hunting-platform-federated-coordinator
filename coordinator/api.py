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

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.security import APIKeyHeader, HTTPBearer
from pydantic import BaseModel, Field

from flproto.attestation import (
    build_global_model_attestation, build_round_announcement_attestation,
    build_trust_notification_attestation, generate_challenge,
    public_key_from_pem, public_key_to_pem, sign as att_sign, verify as att_verify,
)
from flproto.ca import (
    cert_to_pem, issue_client_cert,
)
from coordinator.aggregation import merge_xgboost_models
from coordinator.security import FLAuthManager, FLUser, generate_fl_api_key

router = APIRouter(prefix="/fl", tags=["fl-coordinator"])

# Reject oversized uploads up front (DoS / memory-exhaustion guard, SR-06).
# Override via FL_MAX_MODEL_BYTES. 64 MiB comfortably fits a 500-tree ensemble.
import os as _os
_MAX_MODEL_BYTES = int(_os.environ.get("FL_MAX_MODEL_BYTES", 64 * 1024 * 1024))

_bearer  = HTTPBearer(auto_error=False)
_api_key = APIKeyHeader(name="X-FL-API-Key", auto_error=False)


# ── Auth dependencies (separate from api/middleware.py — different boundary) ─

async def get_fl_user(
    request: Request,
    bearer  = Depends(_bearer),
    api_key = Depends(_api_key),
) -> FLUser:
    auth_manager: FLAuthManager = request.app.state.fl_auth_manager
    if bearer and bearer.credentials:
        user = auth_manager.verify_jwt(bearer.credentials)
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

    # Fallback to API-key bootstrap auth
    if api_key:
        store = _store(request)
        for org in store.list_orgs():
            if org["status"] != "active":
                continue
            api_hash = hashlib.sha256(api_key.encode()).hexdigest()
            import hmac as _hmac
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
    _audit(request).log("fl.org.revoke", user.username, org_id, {})
    return {"org_id": org_id, "status": "revoked"}


# ── Rounds ─────────────────────────────────────────────────────────────────

@router.post("/rounds/start", status_code=202)
async def start_round(
    body: StartRoundRequest,
    request: Request,
    user: FLUser = Depends(fl_require("fl_start_round")),
):
    """
    Create a new FL round record. The actual gRPC orchestration is done
    by the Flower server alongside this API; this endpoint records the
    intent + parameters + invited orgs for audit.
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

    round_id = store.start_round(
        started_by=user.username,
        params=body.model_dump(),
        invited_count=len(invited),
    )
    _audit(request).log(
        action="fl.round.start",
        actor=user.username,
        target=f"round_{round_id}",
        details={
            "epsilon":         body.epsilon,
            "num_boost_rounds": body.num_boost_rounds,
            "invited_orgs":    [o["org_id"] for o in invited],
        },
    )
    return {
        "round_id":      round_id,
        "status":        "running",
        "invited_orgs":  [o["org_id"] for o in invited],
        "params":        body.model_dump(),
    }


@router.get("/rounds")
async def list_rounds(
    request: Request,
    limit: int = 50,
    user: FLUser = Depends(fl_require("fl_view_rounds")),
):
    return {"rounds": _store(request).list_rounds(limit=limit)}


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


@router.get("/rounds/{round_id}/global-model")
async def get_global_model(
    round_id: int,
    request: Request,
    org_id: str = Depends(get_authenticated_org_id),
):
    """
    Return the aggregated global model for this round, with a coordinator
    signature so the org can verify it wasn't tampered or forged.

    The signed_attestation field contains the EXACT bytes the coordinator
    signed (org should NOT re-canonicalise — verify against these bytes).
    """
    store = _store(request)
    r = store.get_round(round_id)
    if not r:
        raise HTTPException(404, f"Round not found: {round_id}")
    if r["status"] != "completed":
        raise HTTPException(409, f"Round {round_id} not completed yet")

    # Pull the model from disk (coordinator stores aggregated models per round)
    from pathlib import Path
    model_dir = Path(request.app.state.fl_model_dir)
    model_path = model_dir / f"round_{round_id}.json"
    if not model_path.exists():
        raise HTTPException(404, f"Aggregated model file missing for round {round_id}")
    model_bytes = model_path.read_bytes()

    # Build + sign the attestation with the coordinator's private key
    accepted_orgs = [
        c["org_id"] for c in store.list_contributions(round_id=round_id)
        if c["accepted"]
    ]
    att_bytes = build_global_model_attestation(
        round_id=round_id,
        model_bytes=model_bytes,
        accepted_org_ids=sorted(set(accepted_orgs)),
    )
    sig = att_sign(request.app.state.fl_coord_priv, att_bytes)

    import base64
    return {
        "round_id":           round_id,
        "model_b64":          base64.b64encode(model_bytes).decode(),
        "signed_attestation": att_bytes.decode("utf-8"),
        "signature_hex":      sig.hex(),
    }


# ── Aggregation (combine accepted matrices into the global model) ───────────

@router.post("/rounds/{round_id}/aggregate")
async def aggregate_round(
    round_id: int,
    request: Request,
    user: FLUser = Depends(fl_require("fl_aggregate_round")),
):
    """
    Combine every accepted contribution for a round into one global model.

    Pipeline:
      1. Round must be 'running'.
      2. Load each accepted contribution's persisted model bytes.
      3. Trust-validate each (structure + public-validation accuracy + sudden-
         drop poisoning check); persist updated trust scores; EXCLUDE orgs
         below the trust floor (SR-05).
      4. Federated-bagging merge of survivors, weighted by trust x num_examples.
      5. Persist round_{id}.json, mark the round completed, audit.

    The aggregated model is then served, coordinator-signed, by
    GET /rounds/{round_id}/global-model.
    """
    from pathlib import Path

    store = _store(request)
    r = store.get_round(round_id)
    if not r:
        raise HTTPException(404, f"Round not found: {round_id}")
    if r["status"] != "running":
        raise HTTPException(409, f"Round {round_id} is not running ({r['status']})")

    tm = getattr(request.app.state, "trust_manager", None)
    if tm is None:
        raise HTTPException(503, "Trust manager not initialised")

    accepted = store.get_accepted_models(round_id)
    if not accepted:
        raise HTTPException(422, "No accepted contributions to aggregate")

    coord_priv = request.app.state.fl_coord_priv
    weighted: list[tuple[bytes, float]] = []
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
            weighted.append((mb, ev["weight"]))
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

    if not weighted:
        # Everyone failed validation — leave the round running for the operator
        # to investigate. Trust changes have already been persisted.
        raise HTTPException(
            422,
            "All accepted contributions were rejected by trust validation; "
            "round left running",
        )

    global_bytes, info = merge_xgboost_models(weighted)
    model_dir = Path(request.app.state.fl_model_dir)
    (model_dir / f"round_{round_id}.json").write_bytes(global_bytes)
    global_hash = hashlib.sha256(global_bytes).hexdigest()

    survivors = [x["org_id"] for x in results if x["accepted"]]
    store.complete_round(
        round_id, status="completed",
        responded=len(accepted), accepted=len(survivors),
        rejected=len(accepted) - len(survivors),
        global_model_hash=global_hash,
        eval_metrics={"merge": info, "contributors": results},
    )
    _audit(request).log(
        action="fl.round.aggregated", actor=user.username,
        target=f"round_{round_id}",
        details={"global_model_sha256": global_hash[:16],
                 "accepted": survivors, "total_trees": info["total_trees"]},
    )
    return {
        "round_id":            round_id,
        "status":              "completed",
        "global_model_sha256": global_hash,
        "accepted_orgs":       survivors,
        "rejected":            [x for x in results if not x["accepted"]],
        "merge":               info,
        "trust_updates":       trust_updates,
    }


# ── Audit ──────────────────────────────────────────────────────────────────

@router.get("/audit")
async def view_audit(
    request: Request,
    limit: int = 100,
    user: FLUser = Depends(fl_require("fl_view_audit")),
):
    """FL coordinator audit trail. Separate from org platform's audit DB."""
    return {"entries": _audit(request).query(limit=limit)}
