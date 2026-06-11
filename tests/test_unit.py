"""
Unit tests for the security/merge core — no HTTP, no xgboost.

Run:  PYTHONPATH=. pytest tests/test_unit.py
"""

import json
import tempfile

from flproto.attestation import (
    canonical_json, generate_keypair, sign, verify, generate_challenge,
    build_contribution_attestation,
)
from flproto.ca import (
    init_ca, load_ca, issue_client_cert, verify_cert_signed_by_ca,
    build_crl, is_revoked, cert_org_id, public_key_from_pem,
)
from coordinator.aggregation import merge_xgboost_models, _get_trees
from coordinator.store import CoordinatorStore
from client_ref.privacy import apply_differential_privacy


# ── Canonical JSON + signatures ────────────────────────────────────────────

def test_canonical_json_is_deterministic():
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2})


def test_sign_verify_and_forgery_rejected():
    priv, pub = generate_keypair()
    msg = canonical_json({"x": 1})
    sig = sign(priv, msg)
    assert verify(pub, msg, sig) is True
    assert verify(pub, msg + b"!", sig) is False           # tampered message
    other_priv, _ = generate_keypair()
    assert verify(pub, msg, sign(other_priv, msg)) is False  # wrong key


def test_contribution_attestation_binds_model_hash():
    att = build_contribution_attestation(
        round_id=3, org_id="udom", model_bytes=b"model-A",
        num_examples=10, challenge="ab")
    import hashlib
    assert json.loads(att)["model_sha256"] == hashlib.sha256(b"model-A").hexdigest()


# ── CA + CRL ────────────────────────────────────────────────────────────────

def test_ca_issues_and_crl_revokes():
    with tempfile.TemporaryDirectory() as d:
        init_ca(d, coordinator_hostname="localhost")
        ca_priv, ca_cert = load_ca(d)
        _, org_pub = generate_keypair()
        cert = issue_client_cert(ca_priv=ca_priv, ca_cert=ca_cert,
                                 client_pub=org_pub, org_id="bank-x")
        assert verify_cert_signed_by_ca(cert, ca_cert) is True
        assert cert_org_id(cert) == "bank-x"
        crl = build_crl(ca_priv, ca_cert, revoked_serials=[cert.serial_number])
        assert is_revoked(crl, cert.serial_number) is True


# ── Replay protection (one-shot nonce) ─────────────────────────────────────

def test_challenge_is_single_use_and_bound():
    with tempfile.TemporaryDirectory() as d:
        store = CoordinatorStore(db_path=f"{d}/c.db")
        store.enroll_org("udom", "UDOM", "hash", "admin")
        ch = generate_challenge()
        store.issue_challenge("udom", 1, ch)
        assert store.consume_challenge(ch, "udom", 1) is None          # first ok
        assert store.consume_challenge(ch, "udom", 1) == "Challenge already consumed"
        ch2 = generate_challenge()
        store.issue_challenge("udom", 1, ch2)
        assert store.consume_challenge(ch2, "other", 1) == "Challenge belongs to a different org"


# ── Federated bagging merge ─────────────────────────────────────────────────

def _mk_model(n_trees: int, tag: str) -> bytes:
    trees = [{"id": i, "tag": tag} for i in range(n_trees)]
    return json.dumps({"learner": {"gradient_booster": {"model": {
        "trees": trees, "tree_info": [0] * n_trees,
        "iteration_indptr": list(range(n_trees + 1)),
        "gbtree_model_param": {"num_trees": str(n_trees)},
    }}}}).encode()


def test_merge_concatenates_and_renumbers():
    a = _mk_model(10, "A")   # heaviest -> structural base
    b = _mk_model(10, "B")
    merged, info = merge_xgboost_models([(a, 800.0), (b, 200.0)])
    mj = json.loads(merged)
    trees = _get_trees(mj)
    # base 10 + ceil(200/1000 * 10)=2 from B
    assert len(trees) == 12
    assert [t["id"] for t in trees] == list(range(12))     # sequential ids (no segfault)
    assert mj["learner"]["gradient_booster"]["model"]["gbtree_model_param"]["num_trees"] == "12"
    assert info["total_trees"] == 12 and info["num_models"] == 2


def test_merge_caps_at_500():
    a = _mk_model(400, "A")
    b = _mk_model(400, "B")
    merged, info = merge_xgboost_models([(a, 1.0), (b, 1.0)])
    assert info["capped"] is True
    assert len(_get_trees(json.loads(merged))) == 500


def test_merge_rejects_empty():
    try:
        merge_xgboost_models([(b"not-json", 1.0)])
        assert False, "expected ValueError"
    except ValueError:
        pass


# ── Differential privacy ────────────────────────────────────────────────────

def test_dp_perturbs_leaves_but_keeps_json():
    model = json.dumps({"learner": {"gradient_booster": {"model": {"trees": [{
        "split_conditions": [0.5, 1.5], "left_children": [-1, -1],
    }]}}}}).encode()
    out = apply_differential_privacy(model, epsilon=1.0)
    assert out != model                          # leaves changed
    json.loads(out)                              # still valid JSON


if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("PASS", fn.__name__)
    print(f"\n{len(fns)} unit tests passed")
    sys.exit(0)
