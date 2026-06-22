"""
Operator dashboard E2E: login -> render pages -> drive an action via the cookie
-> verify it lands in the hash-chained audit -> logout. Proves the web console
reuses the same RBAC + audit as the programmatic API (cookie auth on /fl/*).

Run:  PYTHONPATH=. OMP_NUM_THREADS=1 python tests/test_dashboard.py
"""

import hashlib
import os
import tempfile

import yaml

_TMP = tempfile.mkdtemp(prefix="flcoord_dash_")

from flproto.ca import init_ca  # noqa: E402
_CA_DIR = os.path.join(_TMP, "ca")
init_ca(_CA_DIR, coordinator_hostname="localhost")

ADMIN_KEY = "dash-operator-key"
_users = {"users": [{"username": "root", "role": "fl_admin",
                     "api_key_hash": hashlib.sha256(ADMIN_KEY.encode()).hexdigest()}]}
_USERS_FILE = os.path.join(_TMP, "users.yml")
with open(_USERS_FILE, "w") as f:
    f.write(yaml.safe_dump(_users))

os.environ.update({
    "FL_DATA_DIR": _TMP, "FL_CA_DIR": _CA_DIR, "FL_USERS_FILE": _USERS_FILE,
    "FL_JWT_SECRET": "test-secret-at-least-32-bytes-long!!",
    "FL_DEV_ALLOW_HEADER_MTLS": "1", "FL_OBSERVATION_HOURS": "0", "OMP_NUM_THREADS": "1",
})

from fastapi.testclient import TestClient                       # noqa: E402
from coordinator.app import app                                 # noqa: E402
from flproto.attestation import generate_keypair, public_key_to_pem  # noqa: E402

client = TestClient(app)


def test_dashboard():
    # ── unauthenticated ──────────────────────────────────────────────────────
    assert client.get("/login").status_code == 200
    assert "Sign in" in client.get("/login").text
    r = client.get("/dashboard", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login", r.status_code
    # /fl/* without auth is refused
    assert client.get("/fl/orgs").status_code == 401

    # ── bad + good login ─────────────────────────────────────────────────────
    r = client.post("/login", data={"username": "root", "api_key": "wrong"},
                    follow_redirects=False)
    assert r.status_code == 303 and "error" in r.headers["location"]
    r = client.post("/login", data={"username": "root", "api_key": ADMIN_KEY},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/dashboard", r.text
    assert client.cookies.get("fl_session"), "login must set the session cookie"

    # ── every page renders for the authenticated operator ────────────────────
    for path in ("/dashboard", "/dashboard/orgs", "/dashboard/rounds",
                 "/dashboard/models", "/dashboard/audit"):
        resp = client.get(path)
        assert resp.status_code == 200, f"{path} -> {resp.status_code}"
        assert "FL Coordinator" in resp.text

    # ── the cookie authenticates the SAME /fl/* API the dashboard calls ──────
    assert client.get("/fl/orgs").status_code == 200
    _, pub = generate_keypair()
    r = client.post("/fl/orgs/enroll", json={
        "org_id": "udom", "display_name": "UDOM",
        "public_key_pem": public_key_to_pem(pub).decode()})
    assert r.status_code == 201, r.text                    # cookie-authed mutation
    # round detail page renders for a real round
    rid = client.post("/fl/rounds/start", json={"min_clients": 1}).json()["round_id"]
    assert client.get(f"/dashboard/rounds/{rid}").status_code == 200

    # ── audit: login + the enroll are in the hash-chained trail ──────────────
    actions = [e["action"] for e in client.get("/fl/audit?limit=50").json()["entries"]]
    assert "fl.operator.login" in actions, actions
    assert "fl.org.enroll" in actions, actions
    assert app.state.fl_audit_trail.verify_integrity()[0], "audit chain broken"

    # ── logout clears the cookie + is audited ────────────────────────────────
    r = client.post("/logout", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert "fl.operator.logout" in [
        e["action"] for e in app.state.fl_audit_trail.query(limit=5)]
    # cookie gone -> pages redirect again
    client.cookies.clear()
    assert client.get("/dashboard", follow_redirects=False).status_code == 303
    return len(actions)


if __name__ == "__main__":
    n = test_dashboard()
    print("PASS test_dashboard (login -> pages -> cookie action -> audit -> logout)")
    print(f"  audit actions recorded this session: {n}")
