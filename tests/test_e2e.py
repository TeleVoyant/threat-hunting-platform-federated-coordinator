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
    "FL_OBSERVATION_HOURS": "0",          # no intake/soak wait in tests
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
    start_resp = r.json()
    rid = start_resp["round_id"]

    # Round announcement: coordinator-signed and verifiable by an invited org.
    from flproto.attestation import public_key_from_pem as _pkfp, verify as _att_verify
    ann = start_resp["round_announcement"]
    assert ann is not None, "start_round should emit a signed round announcement"
    assert _att_verify(_pkfp(coord_pub_pem), ann["signed_attestation"].encode(),
                       bytes.fromhex(ann["signature_hex"])), "announcement signature must verify"
    r_ann = client.get(f"/fl/rounds/{rid}/announcement", headers=_org_hdr("orgA"))
    assert r_ann.status_code == 200, r_ann.text
    assert r_ann.json()["signed_attestation"] == ann["signed_attestation"]

    # round discovery: orgA finds the open round it was invited to.
    disc = client.get("/fl/rounds/active", headers=_org_hdr("orgA")).json()
    assert rid in [x["round_id"] for x in disc["active_rounds"]], disc

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

    # aggregate (operator/admin) -> STAGES a global model (round -> 'aggregated').
    r = client.post(f"/fl/rounds/{rid}/aggregate", headers=ADMIN)
    assert r.status_code == 200, r.text
    agg = r.json()
    assert agg["status"] == "aggregated" and agg.get("version_id"), agg
    assert set(agg["accepted_orgs"]) == {"orgA", "orgB"}, agg
    assert agg["merge"]["total_trees"] > 0

    # the staged model is NOT served to orgs until it is published.
    assert client.get("/fl/global-model", headers=_org_hdr("orgA")).status_code == 404

    # publish (operator) -> promote staged to active (FL_OBSERVATION_HOURS=0).
    r = client.post(f"/fl/rounds/{rid}/publish", headers=ADMIN)
    assert r.status_code == 200 and r.json()["status"] == "active", r.text

    # now the active global model is served + verifies (signature + hash).
    r = client.get("/fl/global-model", headers=_org_hdr("orgA"))
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

    # FL_REQUIRE_MTLS refuses the bootstrap api-key fallback for org endpoints.
    a_key = a_enr["api_key"]
    r = client.get(f"/fl/rounds/{rid}/announcement", headers={"X-FL-API-Key": a_key})
    assert r.status_code == 200, f"api-key fallback should work when FL_REQUIRE_MTLS off: {r.text}"
    os.environ["FL_REQUIRE_MTLS"] = "1"
    try:
        r = client.get(f"/fl/rounds/{rid}/announcement", headers={"X-FL-API-Key": a_key})
        assert r.status_code == 401, \
            f"api-key fallback must be refused when FL_REQUIRE_MTLS on, got {r.status_code}"
    finally:
        os.environ.pop("FL_REQUIRE_MTLS", None)

    # audit chain intact.
    integrity_ok = app.state.fl_audit_trail.verify_integrity()[0]
    assert integrity_ok, "audit hash-chain broken"
    return agg


def test_versioning_and_rollback():
    """Two rounds -> two published global-model versions; rollback re-activates
    the first; /models history + the served active model reflect it."""
    v_priv, _ = _enroll("orgV")

    def _round_and_publish():
        rid = client.post("/fl/rounds/start", json={"min_clients": 1},
                          headers=ADMIN).json()["round_id"]
        model, n = train_local_model(PATHS["orgA"], num_boost_round=6, epsilon=1.0)
        ch = client.get(f"/fl/rounds/{rid}/challenge",
                        headers=_org_hdr("orgV")).json()["challenge"]
        att, sig = build_signed_contribution(
            private_key_to_pem(v_priv), round_id=rid, org_id="orgV",
            model_bytes=model, num_examples=n, challenge=ch)
        assert client.post(f"/fl/rounds/{rid}/contribute",
            data={"attestation": att.decode(), "signature": sig},
            files={"model": ("m.json", model, "application/json")},
            headers=_org_hdr("orgV")).status_code == 202
        agg = client.post(f"/fl/rounds/{rid}/aggregate", headers=ADMIN).json()
        pub = client.post(f"/fl/rounds/{rid}/publish", headers=ADMIN).json()
        assert pub["status"] == "active", pub
        return rid, agg["version_id"]

    rid1, v1 = _round_and_publish()
    rid2, v2 = _round_and_publish()
    assert v2 != v1

    models = client.get("/fl/models", headers=ADMIN).json()
    assert models["active"]["version_id"] == v2, models
    status_by_id = {m["version_id"]: m["status"] for m in models["models"]}
    assert status_by_id[v1] == "archived" and status_by_id[v2] == "active", status_by_id

    # roll back to the first version.
    rb = client.post(f"/fl/models/{v1}/rollback", headers=ADMIN)
    assert rb.status_code == 200 and rb.json()["status"] == "active", rb.text
    assert client.get("/fl/models", headers=ADMIN).json()["active"]["version_id"] == v1

    # the active model now served to orgs comes from v1's round.
    served = client.get("/fl/global-model", headers=_org_hdr("orgV")).json()
    assert served["round_id"] == rid1 and served["version_id"] == v1, served
    return v1, v2


def test_observation_window_blocks_aggregate():
    """A non-zero intake/observation window refuses aggregation until it elapses."""
    w_priv, _ = _enroll("orgW")
    rid = client.post("/fl/rounds/start",
                      json={"min_clients": 1, "observation_hours": 1},
                      headers=ADMIN).json()["round_id"]
    model, n = train_local_model(PATHS["orgA"], num_boost_round=4, epsilon=1.0)
    ch = client.get(f"/fl/rounds/{rid}/challenge", headers=_org_hdr("orgW")).json()["challenge"]
    att, sig = build_signed_contribution(
        private_key_to_pem(w_priv), round_id=rid, org_id="orgW",
        model_bytes=model, num_examples=n, challenge=ch)
    assert client.post(f"/fl/rounds/{rid}/contribute",
        data={"attestation": att.decode(), "signature": sig},
        files={"model": ("m.json", model, "application/json")},
        headers=_org_hdr("orgW")).status_code == 202
    # the 1h intake window has not elapsed -> aggregate is refused.
    r = client.post(f"/fl/rounds/{rid}/aggregate", headers=ADMIN)
    assert r.status_code == 409 and "intake" in r.json()["detail"].lower(), r.text


if __name__ == "__main__":
    agg = test_full_round()
    print("PASS test_full_round")
    print(f"  accepted_orgs : {agg['accepted_orgs']}")
    print(f"  global trees  : {agg['merge']['total_trees']}")
    print(f"  trust_updates : {len(agg['trust_updates'])} signed notifications")
    v1, v2 = test_versioning_and_rollback()
    print(f"PASS test_versioning_and_rollback (v{v1} <- rolled back from v{v2})")
    test_observation_window_blocks_aggregate()
    print("PASS test_observation_window_blocks_aggregate")
    print("\nE2E flow passed (enroll -> discover -> sign -> submit -> "
          "aggregate[stage] -> publish -> verify -> rollback)")
