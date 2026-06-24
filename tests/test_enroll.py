"""
Token-based self-enrollment over the FastAPI app (in-process TestClient).

operator mints a token -> org generates Ed25519 + X25519 keys, signs a PoP,
redeems the token -> coordinator verifies token + PoP, issues cert + api_key,
returns the package SEALED to the org's X25519 key -> org unseals + verifies the
CA fingerprint. Negatives: bad PoP (token NOT burned), org_id mismatch, tampered
token, reused token, mint-for-active-org, store-level expiry + single-use.

Run:  PYTHONPATH=. python tests/test_enroll.py
"""

import hashlib
import json
import os
import tempfile
import time

import yaml

_TMP = tempfile.mkdtemp(prefix="flcoord_enr_")

from flproto.ca import init_ca  # noqa: E402
_CA_DIR = os.path.join(_TMP, "ca")
init_ca(_CA_DIR, coordinator_hostname="localhost")

ADMIN_KEY = "admin-bootstrap-key-for-tests"
_users = {"users": [{"username": "root", "role": "fl_admin",
                     "api_key_hash": hashlib.sha256(ADMIN_KEY.encode()).hexdigest()}]}
_USERS_FILE = os.path.join(_TMP, "users.yml")
with open(_USERS_FILE, "w") as f:
    f.write(yaml.safe_dump(_users))

os.environ.update({
    "FL_DATA_DIR": _TMP, "FL_CA_DIR": _CA_DIR, "FL_USERS_FILE": _USERS_FILE,
    "FL_JWT_SECRET": "test-secret-at-least-32-bytes-long!!",
    "FL_DEV_ALLOW_HEADER_MTLS": "1", "FL_OBSERVATION_HOURS": "0",
})

from fastapi.testclient import TestClient                          # noqa: E402
from coordinator.app import app                                    # noqa: E402
from flproto.attestation import (                                  # noqa: E402
    generate_keypair, public_key_to_pem, sign as _sign, build_enroll_pop,
)
from flproto.seal_box import (                                     # noqa: E402
    generate_x25519_keypair, x25519_public_to_pem, x25519_private_to_pem, unseal,
)

client = TestClient(app)
ADMIN = {"X-FL-API-Key": ADMIN_KEY}


def _mint(org_id="orgX", display="Org X", ttl=60):
    r = client.post("/fl/orgs/enroll-token",
                    json={"org_id": org_id, "display_name": display, "ttl_minutes": ttl},
                    headers=ADMIN)
    assert r.status_code == 201, r.text
    return r.json()


def _org_keys():
    ed_priv, ed_pub = generate_keypair()
    x_priv, x_pub = generate_x25519_keypair()
    return (ed_priv, public_key_to_pem(ed_pub).decode(),
            x_priv, x25519_public_to_pem(x_pub).decode())


def _body(token, org_id, ed_priv, ed_pub_pem, x_pub_pem, signer=None):
    pop = build_enroll_pop(token_b64=token, x25519_pub_pem=x_pub_pem)
    return {"token": token, "org_id": org_id, "ed25519_pub_pem": ed_pub_pem,
            "x25519_pub_pem": x_pub_pem, "pop_signature": _sign(signer or ed_priv, pop).hex()}


def test_self_enroll():
    mint = _mint("orgX", "Org X")
    token, ca_sha256 = mint["token"], mint["ca_sha256"]
    ed_priv, ed_pub_pem, x_priv, x_pub_pem = _org_keys()

    # bad PoP (signed with a different key) -> 403, token NOT consumed
    bad_priv, _ = generate_keypair()
    rbad = client.post("/fl/orgs/enroll-with-token",
                       json=_body(token, "orgX", ed_priv, ed_pub_pem, x_pub_pem, signer=bad_priv))
    assert rbad.status_code == 403, ("bad PoP must 403", rbad.status_code, rbad.text)

    # org_id mismatch -> 400 (caught before consume)
    rmm = client.post("/fl/orgs/enroll-with-token",
                      json=_body(token, "orgY", ed_priv, ed_pub_pem, x_pub_pem))
    assert rmm.status_code == 400, ("org_id mismatch must 400", rmm.status_code, rmm.text)

    # tampered token -> rejected
    bad_token = token[:-4] + ("AAAA" if token[-4:] != "AAAA" else "BBBB")
    rt = client.post("/fl/orgs/enroll-with-token",
                     json=_body(bad_token, "orgX", ed_priv, ed_pub_pem, x_pub_pem))
    assert rt.status_code in (400, 403), ("tampered token rejected", rt.status_code, rt.text)

    # valid enroll -> 201 sealed; unseal; verify fingerprint + package
    ok = client.post("/fl/orgs/enroll-with-token",
                     json=_body(token, "orgX", ed_priv, ed_pub_pem, x_pub_pem))
    assert ok.status_code == 201, ok.text
    pkg = json.loads(unseal(x25519_private_to_pem(x_priv), ok.json()["sealed_package_b64"]))
    assert pkg["org_id"] == "orgX" and pkg["api_key"] and pkg["client_cert_pem"], pkg.keys()
    assert hashlib.sha256(pkg["ca_cert_pem"].encode()).hexdigest() == ca_sha256, \
        "unsealed CA fingerprint must match the mint ca_sha256"

    # reused token -> rejected (jti consumed)
    rr = client.post("/fl/orgs/enroll-with-token",
                     json=_body(token, "orgX", ed_priv, ed_pub_pem, x_pub_pem))
    assert rr.status_code in (403, 409), ("reused token must be rejected", rr.status_code, rr.text)

    # the enrolled org is active + authenticates with the issued api-key
    ar = client.get("/fl/rounds/active", headers={"X-FL-API-Key": pkg["api_key"]})
    assert ar.status_code == 200, ("enrolled org api-key must work", ar.status_code, ar.text)

    # minting a token for an already-active org -> 409
    m2 = client.post("/fl/orgs/enroll-token",
                     json={"org_id": "orgX", "display_name": "x", "ttl_minutes": 60}, headers=ADMIN)
    assert m2.status_code == 409, ("mint for active org must 409", m2.text)

    print("PASS test_self_enroll")


def test_token_store_expiry_and_single_use():
    from coordinator.store import CoordinatorStore
    st = CoordinatorStore(db_path=os.path.join(_TMP, "exp.db"))
    st.create_enroll_token("jtiexp", "orgZ", "Z", time.time() - 1)        # already expired
    assert st.consume_enroll_token("jtiexp", "orgZ") == "Token expired"
    st.create_enroll_token("jti2", "orgZ", "Z", time.time() + 60)
    assert st.consume_enroll_token("jti2", "orgZ") is None                # ok
    assert st.consume_enroll_token("jti2", "orgZ") == "Token already used"  # single-use
    assert st.consume_enroll_token("nope", "orgZ") == "Unknown enrollment token"
    print("PASS test_token_store_expiry_and_single_use")


if __name__ == "__main__":
    test_self_enroll()
    test_token_store_expiry_and_single_use()
    print("ALL ENROLL TESTS PASSED")
