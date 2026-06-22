# coordinator/app.py
"""
Standalone FL Coordinator entry point (apt-fl-coordinator).

Runs the FastAPI management + matrix-exchange API on its own port (default
8889). It is a SEPARATE trust boundary from any participating organisation's
platform: own JWT secret, own user roster, own audit DB, own CA.

Config (env vars; *_FILE variants read a Docker secret file instead):

  FL_JWT_SECRET / FL_JWT_SECRET_FILE   operator JWT secret (>=32 bytes)
  FL_USERS_FILE        YAML FL operator roster (config/fl_users.example.yml)
  FL_DATA_DIR          base dir for DB + audit + models (default: data/fl_coordinator)
  FL_CA_DIR            federation CA material (default: $FL_DATA_DIR/ca)
  FL_MODEL_DIR         per-round contributions + aggregated models
  FL_VALIDATION_DATA   path to a PUBLIC/synthetic XGBoost DMatrix (libsvm) used
                       for trust/poisoning scoring; unset => structure-only trust
  FL_API_PORT          default 8889

This module imports NO monorepo packages and shares no state with any org
platform — it can be deployed on a wholly separate host.
"""

import os
import sys
from pathlib import Path

import yaml
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flproto.ca                  import load_ca, load_coordinator_keypair, load_crl
from coordinator.api             import router as fl_router
from coordinator.dashboard       import router as dashboard_router
from coordinator.store           import CoordinatorStore
from coordinator.security        import FLAuthManager, FLRole, FLUser
from coordinator.mtls_middleware import MTLSMiddleware
from coordinator.audit           import AuditTrail
from coordinator.trust           import TrustManager
from coordinator.logging         import get_logger, setup_logging

logger = get_logger("coordinator.app")


def _read_secret(name: str, default: str = "") -> str:
    """Read a secret from $NAME_FILE (Docker secret) if present, else $NAME.
    Docker secrets are mounted as files under /run/secrets — never in env or
    the image (SR-02)."""
    path = os.environ.get(f"{name}_FILE")
    if path and Path(path).exists():
        return Path(path).read_text().strip()
    return os.environ.get(name, default)


def _load_validation_data(logger):
    """Load the coordinator's PUBLIC validation DMatrix for trust scoring.
    Returns None (structure-only trust) when unset or xgboost is unavailable."""
    vpath = os.environ.get("FL_VALIDATION_DATA")
    if not vpath:
        logger.warning("FL_VALIDATION_DATA unset — trust runs in structure-only mode")
        return None
    if not Path(vpath).exists():
        logger.error("FL_VALIDATION_DATA path missing — structure-only trust", path=vpath)
        return None
    try:
        import xgboost as xgb
        from flproto.dataset import load_libsvm
        X, y = load_libsvm(vpath)                       # array-based (portable, no file iterator)
        dmat = xgb.DMatrix(X, label=y, nthread=1)
        logger.info("Validation set loaded", path=vpath, rows=dmat.num_row())
        return dmat
    except Exception as e:
        logger.error("Failed to load validation set — structure-only trust", error=str(e))
        return None


def build_app() -> FastAPI:
    setup_logging("INFO")

    data_dir = os.environ.get("FL_DATA_DIR", "data/fl_coordinator")
    Path(data_dir).mkdir(parents=True, exist_ok=True)

    # ── Load FL user roster ─────────────────────────────────────────────────
    users_file = os.environ.get("FL_USERS_FILE", "config/fl_users.yml")
    if Path(users_file).exists():
        with open(users_file) as f:
            sec = yaml.safe_load(f) or {}
        users = [
            FLUser(username=u["username"],
                   role=FLRole(u["role"]),
                   api_key_hash=u["api_key_hash"])
            for u in sec.get("users", [])
        ]
    else:
        logger.warning("FL_USERS_FILE missing — coordinator boots with no users",
                       path=users_file)
        users = []

    jwt_secret = _read_secret("FL_JWT_SECRET")
    if not jwt_secret or len(jwt_secret) < 32:
        logger.warning(
            "FL_JWT_SECRET missing or short (<32 bytes). Rotate before production."
        )

    fl_auth_manager   = FLAuthManager(jwt_secret=jwt_secret, users=users)
    coordinator_store = CoordinatorStore(db_path=f"{data_dir}/coordinator.db")
    fl_audit_trail    = AuditTrail(db_path=f"{data_dir}/audit.db")

    # ── Load federation CA + coordinator's own keypair + CRL ────────────────
    ca_dir = os.environ.get("FL_CA_DIR", f"{data_dir}/ca")
    fl_ca_priv = fl_ca_cert = fl_coord_priv = fl_coord_cert = fl_crl = None
    if Path(ca_dir).exists() and (Path(ca_dir) / "ca_key.pem").exists():
        try:
            fl_ca_priv,    fl_ca_cert    = load_ca(ca_dir)
            fl_coord_priv, fl_coord_cert = load_coordinator_keypair(ca_dir)
            fl_crl = load_crl(ca_dir)
            logger.info("Federation CA + CRL loaded", ca_dir=ca_dir,
                        ca_subject=fl_ca_cert.subject.rfc4514_string(),
                        coord_subject=fl_coord_cert.subject.rfc4514_string())
        except Exception as e:
            logger.error("Failed to load CA — enrollment will return 503",
                         ca_dir=ca_dir, error=str(e))
    else:
        logger.warning("CA not initialised — run `python -m coordinator.init_ca` "
                       "before enrolling orgs", ca_dir=ca_dir)

    fl_model_dir = os.environ.get("FL_MODEL_DIR", f"{data_dir}/models")
    Path(fl_model_dir).mkdir(parents=True, exist_ok=True)

    # Trust manager: re-scores + weights contributions at aggregation time
    # against a PUBLIC validation set (or structure-only when unset).
    validation_data = _load_validation_data(logger)
    trust_manager = TrustManager(
        coordinator_store,
        validation_data=validation_data,
        max_num_examples=int(os.environ.get("FL_MAX_NUM_EXAMPLES", 1_000_000)),
    )

    app = FastAPI(
        title="APT Platform — FL Coordinator",
        description=(
            "Federated learning coordinator for cross-organization model "
            "aggregation. Separate trust boundary from any participating "
            "organization's platform."
        ),
        version="1.0.0",
    )
    app.state.fl_auth_manager   = fl_auth_manager
    app.state.coordinator_store = coordinator_store
    app.state.fl_audit_trail    = fl_audit_trail
    app.state.fl_ca_priv        = fl_ca_priv
    app.state.fl_ca_cert        = fl_ca_cert
    app.state.fl_coord_priv     = fl_coord_priv
    app.state.fl_coord_cert     = fl_coord_cert
    app.state.fl_crl            = fl_crl
    app.state.fl_model_dir      = fl_model_dir
    app.state.trust_manager     = trust_manager

    # Operator web console (Jinja2 templates under coordinator/templates).
    app.state.templates = Jinja2Templates(
        directory=str(Path(__file__).resolve().parent / "templates"))

    # mTLS middleware enriches every request with request.state.mtls_org_id
    # when a valid client cert is presented. Route dependencies decide
    # whether to require mTLS or fall back to the bootstrap API key.
    app.add_middleware(MTLSMiddleware)

    app.include_router(fl_router)
    app.include_router(dashboard_router)   # /login, /dashboard/* (cookie-auth)

    @app.get("/")
    async def root():
        return {
            "service":    "fl-coordinator",
            "dashboard":  "/dashboard",
            "users_loaded": len(users),
            "active_orgs": sum(
                1 for o in coordinator_store.list_orgs() if o["status"] == "active"
            ),
        }

    logger.info(
        "FL coordinator initialised",
        data_dir=data_dir,
        users_loaded=len(users),
        api_port=int(os.environ.get("FL_API_PORT", 8889)),
    )
    return app


# Module-level instance so `uvicorn federated.coordinator_app:app` works
app = build_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("FL_API_PORT", 8889)),
    )
