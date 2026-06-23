"""
Mutual-ack org removal flow over the FastAPI app (in-process TestClient).

Covers: forgery rejection -> org-signed leave-request -> leave_pending (NOT
invited to rounds) -> operator approve-removal -> revoked + CRL-regenerated +
coordinator-signed removal confirmation -> org polls removal-status -> revoked
org's api-key rejected. Plus approve-only-from-leave_pending, force-revoke
(+CRL), and re-enroll of a revoked org.

Run:  PYTHONPATH=. python tests/test_removal.py
"""

import hashlib
import os
import tempfile

import yaml

_TMP = tempfile.mkdtemp(prefix="flcoord_rm_")

from flproto.ca import init_ca, load_crl, is_revoked  # noqa: E402
_CA_DIR = os.path.join(_TMP, "ca")
init_ca(_CA_DIR, coordinator_hostname="localhost")

ADMIN_KEY = "admin-bootstrap-key-for-tests"
_users = {"users": [{
    "username": "root", "role": "fl_admin",
    "api_key_hash": hashlib.sha256(ADMIN_KEY.encode()).hexdigest(),
}]}
_USERS_FILE = os.path.join(_TMP, "users.yml")
with open(_USERS_FILE, "w") as f:
    f.write(yaml.safe_dump(_users))

os.environ.update({
    "FL_DATA_DIR": _TMP, "FL_CA_DIR": _CA_DIR, "FL_USERS_FILE": _USERS_FILE,
    "FL_JWT_SECRET": "test-secret-at-least-32-bytes-long!!",
    "FL_DEV_ALLOW_HEADER_MTLS": "1", "FL_OBSERVATION_HOURS": "0",
})

from fastapi.testclient import TestClient                       # noqa: E402
from coordinator.app import app                                 # noqa: E402
from flproto.attestation import (                               # noqa: E402
    generate_keypair, public_key_to_pem,
    build_leave_request_attestation, sign as _sign, verify as _vrf,
    public_key_from_pem as _pkfp,
)

client = TestClient(app)
ADMIN = {"X-FL-API-Key": ADMIN_KEY}


def _enroll(org_id):
    priv, pub = generate_keypair()
    r = client.post("/fl/orgs/enroll",
                    json={"org_id": org_id, "display_name": org_id,
                          "public_key_pem": public_key_to_pem(pub).decode()},
                    headers=ADMIN)
    assert r.status_code == 201, r.text
    return priv, r.json()


def _ohdr(o):
    return {"X-Dev-Mtls-Org-Id": o}


def test_mutual_ack_removal():
    priv, enr = _enroll("orgLeave")
    _enroll("orgKeep")                       # an active org so a round can start
    coord_pub = _pkfp(enr["coordinator_pub_pem"].encode())

    # ── Forgery: a different key cannot request leave for orgLeave ───────────
    att = build_leave_request_attestation(org_id="orgLeave")
    bad_priv, _ = generate_keypair()
    rf = client.post("/fl/orgs/orgLeave/leave-request",
                     json={"attestation": att.decode(), "signature": _sign(bad_priv, att).hex()},
                     headers=_ohdr("orgLeave"))
    assert rf.status_code == 403, ("forged leave must be rejected", rf.status_code, rf.text)

    # ── 1. Org signs + submits a genuine leave request ──────────────────────
    att = build_leave_request_attestation(org_id="orgLeave", reason="study complete")
    r = client.post("/fl/orgs/orgLeave/leave-request",
                    json={"attestation": att.decode(), "signature": _sign(priv, att).hex()},
                    headers=_ohdr("orgLeave"))
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "leave_pending"

    # leave_pending org is NOT invited to a new round (orgKeep still is)
    rr = client.post("/fl/rounds/start", json={"min_clients": 1}, headers=ADMIN)
    assert rr.status_code == 202, rr.text
    rid = rr.json()["round_id"]
    invited = rr.json()["invited_orgs"]
    assert "orgLeave" not in invited, ("leave_pending must not be invited", invited)
    assert "orgKeep" in invited

    # ── 2. Operator approves -> revoked + signed confirm + CRL has serial ────
    ap = client.post("/fl/orgs/orgLeave/approve-removal", headers=ADMIN)
    assert ap.status_code == 200, ap.text
    assert ap.json()["status"] == "revoked"
    conf = ap.json()["removal_confirm"]
    assert _vrf(coord_pub, conf["signed_attestation"].encode(),
                bytes.fromhex(conf["signature_hex"])), "removal confirm must verify"
    crl = load_crl(_CA_DIR)
    assert is_revoked(crl, int(enr["cert_serial"])), "revoked cert serial must be in CRL"

    # approve-removal is ONLY valid from leave_pending
    ap2 = client.post("/fl/orgs/orgLeave/approve-removal", headers=ADMIN)
    assert ap2.status_code == 409, ("double-approve must 409", ap2.text)

    # ── 3. Org polls removal-status -> revoked + same signed confirm ────────
    st = client.get("/fl/orgs/orgLeave/removal-status", headers=_ohdr("orgLeave"))
    assert st.status_code == 200, st.text
    assert st.json()["status"] == "revoked"
    assert st.json()["removal_confirm"]["signature_hex"] == conf["signature_hex"]

    # revoked org's bootstrap api-key is rejected on a real org endpoint
    rc = client.get(f"/fl/rounds/{rid}/challenge", headers={"X-FL-API-Key": enr["api_key"]})
    assert rc.status_code in (401, 403), ("revoked org must be denied", rc.status_code, rc.text)

    # ── 4. Force path: operator revoke WITHOUT a leave request (+ CRL) ───────
    _p2, e2 = _enroll("orgForce")
    fr = client.delete("/fl/orgs/orgForce", headers=ADMIN)
    assert fr.status_code == 200 and fr.json()["status"] == "revoked", fr.text
    assert is_revoked(load_crl(_CA_DIR), int(e2["cert_serial"])), "force-revoked serial in CRL"

    # ── 5. Re-enroll a revoked org works (rotates everything) ───────────────
    _p3, e3 = _enroll("orgLeave")
    assert e3["org_id"] == "orgLeave"

    print("PASS test_mutual_ack_removal")


if __name__ == "__main__":
    test_mutual_ack_removal()
    print("ALL REMOVAL TESTS PASSED")
