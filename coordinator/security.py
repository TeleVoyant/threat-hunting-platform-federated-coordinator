# federated/fl_security.py
"""
FL Coordinator authentication & RBAC — INTENTIONALLY SEPARATE from
shared/security.py.

Why separate?
-------------
The FL coordinator is a third-party service that aggregates model
contributions from multiple organizations. Its trust boundary is DIFFERENT
from any single participating org:

  - An organization admin (UDOM, hospital, bank) MUST NOT be able to:
      * see other organizations' contributions or aggregated weights
      * block another organization
      * configure FL round parameters
      * read the FL coordinator's audit log

  - An FL coordinator operator MUST NOT automatically have access to any
    org's local platform, alerts, or telemetry.

These two domains share NOTHING — different JWT secrets, different user
rosters, different audit DBs, different permission matrices.

Roles
-----
  FLViewer    — read-only: list orgs, view round history
  FLOperator  — start/stop rounds, block misbehaving clients
  FLAdmin     — full control: configure DP/trust thresholds, manage roster
"""

import hashlib
import hmac
import secrets
import time
from enum import Enum
from typing import Optional

import jwt
from pydantic import BaseModel


class FLRole(str, Enum):
    """Federation-only roles — DO NOT confuse with shared/security.py roles."""
    VIEWER   = "fl_viewer"
    OPERATOR = "fl_operator"
    ADMIN    = "fl_admin"


# What each role can do on the FL coordinator
FL_PERMISSIONS = {
    FLRole.VIEWER: {
        "fl_view_orgs",
        "fl_view_rounds",
        "fl_view_audit",
    },
    FLRole.OPERATOR: {
        "fl_view_orgs",
        "fl_view_rounds",
        "fl_view_audit",
        "fl_start_round",
        "fl_aggregate_round",    # close a round + combine accepted matrices
        "fl_block_org",
        "fl_unblock_org",
    },
    FLRole.ADMIN: {
        "fl_view_orgs",
        "fl_view_rounds",
        "fl_view_audit",
        "fl_start_round",
        "fl_aggregate_round",
        "fl_block_org",
        "fl_unblock_org",
        "fl_enroll_org",         # add new participating organisation
        "fl_revoke_org",         # permanently revoke an org's enrollment
        "fl_configure_round",    # change DP epsilon, trust thresholds, etc.
        "fl_manage_users",       # add/remove FL coordinator operators
    },
}


class FLUser(BaseModel):
    username:     str
    role:         FLRole
    api_key_hash: str


class FLAuthManager:
    """
    JWT + API-key authentication for the FL coordinator.

    Constructed with its OWN jwt_secret + user list — NOT shared with the
    organization platform's AuthManager.
    """

    def __init__(self, jwt_secret: str, users: list[FLUser]):
        self.jwt_secret = jwt_secret
        self.users = {u.username: u for u in users}

    # ── API-key auth ───────────────────────────────────────────────────────

    def authenticate_api_key(self, api_key: str) -> Optional[FLUser]:
        if not api_key:
            return None
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        for user in self.users.values():
            if hmac.compare_digest(user.api_key_hash, key_hash):
                return user
        return None

    # ── JWT auth ───────────────────────────────────────────────────────────

    def create_jwt(self, user: FLUser, expires_hours: int = 8) -> str:
        payload = {
            "sub":     user.username,
            "role":    user.role.value,
            "iss":     "fl-coordinator",  # distinguishes from org-platform tokens
            "iat":     int(time.time()),
            "exp":     int(time.time()) + (expires_hours * 3600),
        }
        return jwt.encode(payload, self.jwt_secret, algorithm="HS256")

    def verify_jwt(self, token: str) -> Optional[FLUser]:
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        # Reject org-platform tokens that happen to share the secret by accident
        if payload.get("iss") != "fl-coordinator":
            return None
        return self.users.get(payload["sub"])

    def has_permission(self, user: FLUser, permission: str) -> bool:
        return permission in FL_PERMISSIONS.get(user.role, set())


def generate_fl_api_key() -> tuple[str, str]:
    """Returns (api_key, sha256_hash). Hash is what goes in the user roster."""
    key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    return key, key_hash
