"""
Reference federated-learning client for the apt-fl-coordinator.

A participating organisation uses this to: train XGBoost locally on its OWN
data, apply differential privacy, sign its contribution, submit it to the
coordinator over mTLS, then fetch + verify the aggregated global model. No raw
data ever leaves the org — only the (DP-noised) tree structure.

Layered so the security-critical pieces are pure and unit-testable:
  * build_signed_contribution() / verify_global_model()  — pure crypto, no I/O
  * train_local_model()                                  — local XGBoost (lazy import)
  * FLClient                                             — mTLS HTTP session (lazy requests)

An external org can vendor just this file + client_ref/privacy.py + flproto/
into their own platform; it depends on nothing else in this repo.
"""

import base64
import hashlib
import json
from typing import Optional, Tuple

from flproto.attestation import (
    build_contribution_attestation, private_key_from_pem, public_key_from_pem,
    sign, verify,
)
from client_ref.privacy import apply_differential_privacy


# ── Pure, testable security core ───────────────────────────────────────────

def build_signed_contribution(
    org_private_key_pem: bytes,
    *,
    round_id: int,
    org_id: str,
    model_bytes: bytes,
    num_examples: int,
    challenge: str,
) -> Tuple[bytes, str]:
    """
    Build the canonical-JSON contribution attestation and Ed25519-sign it.

    Returns (attestation_bytes, signature_hex). The org MUST ship these EXACT
    attestation bytes to the coordinator (not a re-serialised copy) so the
    signature verifies byte-for-byte. The attestation embeds sha256(model),
    so a MITM cannot swap the model without breaking the signature.
    """
    priv = private_key_from_pem(org_private_key_pem)
    att = build_contribution_attestation(
        round_id=round_id, org_id=org_id, model_bytes=model_bytes,
        num_examples=num_examples, challenge=challenge,
    )
    return att, sign(priv, att).hex()


def verify_global_model(
    coordinator_public_key_pem: bytes,
    *,
    model_bytes: bytes,
    signed_attestation: bytes | str,
    signature_hex: str,
) -> Tuple[bool, str]:
    """
    Verify a downloaded global model is authentic + untampered:
      1. coordinator's Ed25519 signature over the EXACT signed_attestation bytes
      2. sha256(model_bytes) matches the model_sha256 inside the attestation

    Returns (ok, reason). Reject and DO NOT load the model on failure.
    """
    pub = public_key_from_pem(coordinator_public_key_pem)
    att_bytes = signed_attestation if isinstance(signed_attestation, bytes) \
        else signed_attestation.encode("utf-8")
    if not verify(pub, att_bytes, bytes.fromhex(signature_hex)):
        return False, "coordinator signature invalid"
    try:
        att = json.loads(att_bytes)
    except json.JSONDecodeError:
        return False, "signed_attestation is not valid JSON"
    if att.get("model_sha256") != hashlib.sha256(model_bytes).hexdigest():
        return False, "model sha256 does not match signed attestation"
    return True, "ok"


# ── Local training (lazy xgboost) ──────────────────────────────────────────

def train_local_model(
    data_path: str,
    params: Optional[dict] = None,
    num_boost_round: int = 10,
    *,
    epsilon: Optional[float] = 1.0,
) -> Tuple[bytes, int]:
    """
    Train an XGBoost model on a local libsvm/DMatrix file and return
    (model_json_bytes, num_examples). When epsilon is not None, differential
    privacy is applied to the exported model before returning.
    """
    import os
    import tempfile
    import xgboost as xgb
    from flproto.dataset import load_libsvm

    X, y = load_libsvm(data_path)                  # array-based (portable, no file iterator)
    dtrain = xgb.DMatrix(X, label=y, nthread=1)
    params = params or {"objective": "binary:logistic", "max_depth": 4, "eta": 0.1}
    booster = xgb.train(params, dtrain, num_boost_round=num_boost_round)

    # save_model(file) — save_raw("json") segfaults on repeat calls in XGBoost 3.x
    fd, tmp = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        booster.save_model(tmp)
        with open(tmp, "rb") as f:
            model_bytes = f.read()
    finally:
        os.unlink(tmp)

    if epsilon is not None:
        model_bytes = apply_differential_privacy(model_bytes, epsilon=epsilon)
    return model_bytes, int(dtrain.num_row())


# ── mTLS HTTP session (lazy requests) ──────────────────────────────────────

class FLClient:
    """
    Thin mTLS client for the coordinator's org-facing endpoints.

    Identity: present the CA-signed client cert/key (mTLS) for every call. The
    api_key is only for the pre-cert bootstrap window and is sent as
    X-FL-API-Key when no client cert is configured.
    """

    def __init__(
        self,
        base_url: str,
        org_id: str,
        org_private_key_pem: bytes,
        *,
        client_cert: Optional[str] = None,   # path to CA-signed client cert (mTLS)
        client_key: Optional[str] = None,    # path to org private key (PEM)
        ca_cert: Optional[str] = None,       # path to federation CA cert (server trust)
        coordinator_public_key_pem: Optional[bytes] = None,
        api_key: Optional[str] = None,       # bootstrap only
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.org_id = org_id
        self.org_private_key_pem = org_private_key_pem
        self.client_cert = client_cert
        self.client_key = client_key
        self.ca_cert = ca_cert
        self.coord_pub_pem = coordinator_public_key_pem
        self.api_key = api_key
        self.timeout = timeout

    def _session(self):
        import requests
        s = requests.Session()
        if self.client_cert and self.client_key:
            s.cert = (self.client_cert, self.client_key)   # mTLS client identity
        if self.ca_cert:
            s.verify = self.ca_cert                          # pin the federation CA
        if self.api_key and not self.client_cert:
            s.headers["X-FL-API-Key"] = self.api_key
        return s

    def get_challenge(self, round_id: int) -> str:
        r = self._session().get(
            f"{self.base_url}/fl/rounds/{round_id}/challenge", timeout=self.timeout)
        r.raise_for_status()
        return r.json()["challenge"]

    def submit_contribution(self, round_id: int, model_bytes: bytes,
                            num_examples: int) -> dict:
        challenge = self.get_challenge(round_id)
        att, sig_hex = build_signed_contribution(
            self.org_private_key_pem, round_id=round_id, org_id=self.org_id,
            model_bytes=model_bytes, num_examples=num_examples, challenge=challenge)
        files = {"model": ("model.json", model_bytes, "application/json")}
        data = {"attestation": att.decode("utf-8"), "signature": sig_hex}
        r = self._session().post(
            f"{self.base_url}/fl/rounds/{round_id}/contribute",
            data=data, files=files, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def fetch_global_model(self, round_id: int, *, verify_signature: bool = True) -> bytes:
        r = self._session().get(
            f"{self.base_url}/fl/rounds/{round_id}/global-model", timeout=self.timeout)
        r.raise_for_status()
        payload = r.json()
        model_bytes = base64.b64decode(payload["model_b64"])
        if verify_signature:
            if not self.coord_pub_pem:
                raise ValueError("coordinator_public_key_pem required to verify the global model")
            ok, why = verify_global_model(
                self.coord_pub_pem, model_bytes=model_bytes,
                signed_attestation=payload["signed_attestation"],
                signature_hex=payload["signature_hex"])
            if not ok:
                raise ValueError(f"global model verification failed: {why}")
        return model_bytes
