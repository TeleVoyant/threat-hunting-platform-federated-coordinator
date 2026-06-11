"""
End-to-end server flow over the FastAPI app (in-process TestClient).

Exercises the real coordinator: enroll -> start round -> per-org signed
contribution over (dev) mTLS -> trust-validated aggregation -> coordinator-
signed global-model download + verification. Replay and bad-signature paths
are asserted along the way.

mTLS identity is injected via the dev-only X-Dev-Mtls-Org-Id header
(FL_DEV_ALLOW_HEADER_MTLS=1) so the flow is testable without standing up real
TLS; the production mTLS path is exercised by the compose walkthrough.

Run:  PYTHONPATH=. OMP_NUM_THREADS=1 python tests/test_e2e.py
"""

import base64
import hashlib
import json
import os
import tempfile

import numpy as np
import yaml

_TMP = tempfile.mkdtemp(prefix="flcoord_e2e_")


def _write_libsvm(path, X, y):
    with open(path, "w") as f:
        for xi, yi in zip(X, y):
            feats = " ".join(f"{j + 1}:{v:.5f}" for j, v in enumerate(xi))
            f.write(f"{int(yi)} {feats}\n")


# ── Synthetic, linearly-separable-ish binary data: org A / org B / coord val ─
_rng = np.random.default_rng(0)
_N, _D = 600, 8
_X = _rng.normal(size=(_N, _D))
_w = _rng.normal(size=_D)
_y = ((_X @ _w + _rng.normal(scale=0.3, size=_N)) > 0).astype(int)
PATHS = {}
for _name, _sl in [("orgA", slice(0, 250)), ("orgB", slice(250, 500)), ("val", slice(500, 600))]:
    _p = os.path.join(_TMP, f"{_name}.svm")
    _write_libsvm(_p, _X[_sl], _y[_sl])
    PATHS[_name] = _p

# ── Federation CA + FL admin roster ─────────────────────────────────────────
from flproto.ca import init_ca  # noqa: E402
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

# ── Env MUST be set before importing coordinator.app (builds at import) ─────
os.environ.update({
    "FL_DATA_DIR": _TMP,
    "FL_CA_DIR": _CA_DIR,
    "FL_USERS_FILE": _USERS_FILE,
    "FL_JWT_SECRET": "test-secret-at-least-32-bytes-long!!",
    "FL_VALIDATION_DATA": PATHS["val"],
    "FL_DEV_ALLOW_HEADER_MTLS": "1",
    "OMP_NUM_THREADS": "1",
})

from fastapi.testclient import TestClient                       # noqa: E402
from coordinator.app import app                                 # noqa: E402
from flproto.attestation import (                               # noqa: E402
    generate_keypair, private_key_to_pem, public_key_to_pem,
)
from client_ref.fl_client import (                              # noqa: E402
    build_signed_contribution, verify_global_model, train_local_model,
)

client = TestClient(app)
ADMIN = {"X-FL-API-Key": ADMIN_KEY}


def _enroll(org_id):
    priv, pub = generate_keypair()
    body = {"org_id": org_id, "display_name": org_id,
            "public_key_pem": public_key_to_pem(pub).decode()}
    r = client.post("/fl/orgs/enroll", json=body, headers=ADMIN)
    assert r.status_code == 201, r.text
    return priv, r.json()


def _org_hdr(org_id):
    return {"X-Dev-Mtls-Org-Id": org_id}


def test_full_round():
    a_priv, a_enr = _enroll("orgA")
    b_priv, b_enr = _enroll("orgB")
    coord_pub_pem = a_enr["coordinator_pub_pem"].encode()

    r = client.post("/fl/rounds/start", json={"min_clients": 2}, headers=ADMIN)
    assert r.status_code == 202, r.text
    rid = r.json()["round_id"]

    # orgA: a tampered signature must be rejected (consumes that challenge) ...
    model_a, n_a = train_local_model(PATHS["orgA"], num_boost_round=8, epsilon=1.0)
    ch = client.get(f"/fl/rounds/{rid}/challenge", headers=_org_hdr("orgA")).json()["challenge"]
    att, sig = build_signed_contribution(
        private_key_to_pem(a_priv), round_id=rid, org_id="orgA",
        model_bytes=model_a, num_examples=n_a, challenge=ch)
    bad_sig = ("0" if sig[0] != "0" else "1") + sig[1:]
    r = client.post(f"/fl/rounds/{rid}/contribute",
                    data={"attestation": att.decode(), "signature": bad_sig},
                    files={"model": ("m.json", model_a, "application/json")},
                    headers=_org_hdr("orgA"))
    assert r.status_code == 403, f"tampered sig should be 403, got {r.status_code}"

    # reusing that now-consumed challenge must also fail (replay) ...
    r = client.post(f"/fl/rounds/{rid}/contribute",
                    data={"attestation": att.decode(), "signature": sig},
                    files={"model": ("m.json", model_a, "application/json")},
                    headers=_org_hdr("orgA"))
    assert r.status_code == 403, f"replayed challenge should be 403, got {r.status_code}"

    # ... a fresh challenge + correct signature succeeds.
    ch2 = client.get(f"/fl/rounds/{rid}/challenge", headers=_org_hdr("orgA")).json()["challenge"]
    att2, sig2 = build_signed_contribution(
        private_key_to_pem(a_priv), round_id=rid, org_id="orgA",
        model_bytes=model_a, num_examples=n_a, challenge=ch2)
    r = client.post(f"/fl/rounds/{rid}/contribute",
                    data={"attestation": att2.decode(), "signature": sig2},
                    files={"model": ("m.json", model_a, "application/json")},
                    headers=_org_hdr("orgA"))
    assert r.status_code == 202 and r.json()["accepted"], r.text

    # orgB contributes.
    model_b, n_b = train_local_model(PATHS["orgB"], num_boost_round=8, epsilon=1.0)
    chb = client.get(f"/fl/rounds/{rid}/challenge", headers=_org_hdr("orgB")).json()["challenge"]
    attb, sigb = build_signed_contribution(
        private_key_to_pem(b_priv), round_id=rid, org_id="orgB",
        model_bytes=model_b, num_examples=n_b, challenge=chb)
    r = client.post(f"/fl/rounds/{rid}/contribute",
                    data={"attestation": attb.decode(), "signature": sigb},
                    files={"model": ("m.json", model_b, "application/json")},
                    headers=_org_hdr("orgB"))
    assert r.status_code == 202 and r.json()["accepted"], r.text

    # duplicate accepted submission for orgB is blocked (one-per-round).
    chb2 = client.get(f"/fl/rounds/{rid}/challenge", headers=_org_hdr("orgB")).json()["challenge"]
    attb2, sigb2 = build_signed_contribution(
        private_key_to_pem(b_priv), round_id=rid, org_id="orgB",
        model_bytes=model_b, num_examples=n_b, challenge=chb2)
    r = client.post(f"/fl/rounds/{rid}/contribute",
                    data={"attestation": attb2.decode(), "signature": sigb2},
                    files={"model": ("m.json", model_b, "application/json")},
                    headers=_org_hdr("orgB"))
    assert r.status_code == 409, f"duplicate should be 409, got {r.status_code}"

    # aggregate (operator/admin) -> combines both, weighted by trust x examples.
    r = client.post(f"/fl/rounds/{rid}/aggregate", headers=ADMIN)
    assert r.status_code == 200, r.text
    agg = r.json()
    assert set(agg["accepted_orgs"]) == {"orgA", "orgB"}, agg
    assert agg["merge"]["total_trees"] > 0

    # fetch the coordinator-signed global model + verify signature + hash.
    r = client.get(f"/fl/rounds/{rid}/global-model", headers=_org_hdr("orgA"))
    assert r.status_code == 200, r.text
    payload = r.json()
    gmodel = base64.b64decode(payload["model_b64"])
    ok, why = verify_global_model(
        coord_pub_pem, model_bytes=gmodel,
        signed_attestation=payload["signed_attestation"],
        signature_hex=payload["signature_hex"])
    assert ok, f"global model verification failed: {why}"

    # the merged global model loads cleanly in XGBoost (no duplicate-id segfault).
    import xgboost as xgb
    bst = xgb.Booster()
    bst.load_model(bytearray(gmodel))

    # audit chain intact.
    integrity_ok = app.state.fl_audit_trail.verify_integrity()[0]
    assert integrity_ok, "audit hash-chain broken"
    return agg


if __name__ == "__main__":
    agg = test_full_round()
    print("PASS test_full_round")
    print(f"  accepted_orgs : {agg['accepted_orgs']}")
    print(f"  global trees  : {agg['merge']['total_trees']}")
    print(f"  trust_updates : {len(agg['trust_updates'])} signed notifications")
    print("\nE2E flow passed (enroll -> sign -> submit -> aggregate -> verify)")
