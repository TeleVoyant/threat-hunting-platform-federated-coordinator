# federated/attestation.py
"""
Cryptographic primitives for FL message attestation.

Used by both sides:
  Org → Coordinator     : sign each contribution (model + metadata)
  Coordinator → Org     : sign aggregated global model + round announcements
                          + per-org trust-score notifications

Why Ed25519?
  - Small keys (32 B) and signatures (64 B) — cheap to ship
  - Constant-time verification — sidesteps timing attacks
  - No parameter choices — no nonce reuse pitfalls
  - Stable across the cryptography library

Why a separate canonical JSON?
  - The bytes that get signed must be byte-identical on producer and verifier
  - Standard json.dumps with sort_keys + compact separators is deterministic
    enough; we wrap it so callers can't accidentally pass non-canonical bytes

The two builders below produce the EXACT bytes for the two attestation flows.
Anything that signs must call build_*_payload() and sign the returned bytes,
then ship the SAME bytes (not a re-serialised version) for the verifier.
"""

import hashlib
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)


# ── Canonical JSON ─────────────────────────────────────────────────────────

def canonical_json(obj: dict) -> bytes:
    """
    Deterministic serialisation: sorted keys, no whitespace, ASCII-safe.
    The bytes returned here are what gets signed — both sides MUST treat
    these as opaque bytes (do not re-serialise on verify).
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


# ── Keypair lifecycle ──────────────────────────────────────────────────────

def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Fresh Ed25519 keypair. The private key never leaves the org's host."""
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def public_key_to_pem(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def private_key_to_pem(priv: Ed25519PrivateKey) -> bytes:
    """Unencrypted PEM — caller is responsible for storing it encrypted at rest."""
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_from_pem(pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Not an Ed25519 public key")
    return key


def private_key_from_pem(pem: bytes, password: Optional[bytes] = None) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=password)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Not an Ed25519 private key")
    return key


# ── Sign / verify ──────────────────────────────────────────────────────────

def sign(priv: Ed25519PrivateKey, message: bytes) -> bytes:
    return priv.sign(message)


def verify(pub: Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    """Constant-time. Returns False on any failure rather than raising."""
    try:
        pub.verify(signature, message)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


# ── Attestation payload builders (one per flow) ────────────────────────────

def build_contribution_attestation(
    *,
    round_id: int,
    org_id: str,
    model_bytes: bytes,
    num_examples: int,
    challenge: str,
    submitted_at: Optional[str] = None,
) -> bytes:
    """
    Org → Coordinator: bytes that get signed when uploading a contribution.

    Includes the SHA-256 of the model — binding the signature to the exact
    bytes that will be uploaded. A MITM cannot swap the model without
    breaking signature verification.
    """
    payload = {
        "type":          "fl.contribution.v1",
        "round_id":      int(round_id),
        "org_id":        str(org_id),
        "model_sha256":  hashlib.sha256(model_bytes).hexdigest(),
        "num_examples":  int(num_examples),
        "challenge":     str(challenge),
        "submitted_at":  submitted_at or datetime.now(timezone.utc).isoformat(),
    }
    return canonical_json(payload)


def build_global_model_attestation(
    *,
    round_id: int,
    model_bytes: bytes,
    accepted_org_ids: list[str],
    distributed_at: Optional[str] = None,
) -> bytes:
    """
    Coordinator → Org: signed when distributing the aggregated global model
    after a round. Org verifies before loading, so it can't be tampered with
    in transit and can't be a forgery from a coordinator-impersonator.
    """
    payload = {
        "type":            "fl.global_model.v1",
        "round_id":        int(round_id),
        "model_sha256":    hashlib.sha256(model_bytes).hexdigest(),
        "accepted_orgs":   sorted(accepted_org_ids),
        "distributed_at":  distributed_at or datetime.now(timezone.utc).isoformat(),
    }
    return canonical_json(payload)


def build_round_announcement_attestation(
    *,
    round_id: int,
    epsilon: float,
    num_boost_rounds: int,
    invited_org_ids: list[str],
    starts_at: Optional[str] = None,
) -> bytes:
    """
    Coordinator → Org: signed when announcing a new round so orgs can prove
    the round was authorised by the coordinator (no rogue round invites).
    """
    payload = {
        "type":              "fl.round_announce.v1",
        "round_id":          int(round_id),
        "epsilon":           float(epsilon),
        "num_boost_rounds":  int(num_boost_rounds),
        "invited_orgs":      sorted(invited_org_ids),
        "starts_at":         starts_at or datetime.now(timezone.utc).isoformat(),
    }
    return canonical_json(payload)


def build_trust_notification_attestation(
    *,
    org_id: str,
    round_id: int,
    new_trust_score: float,
    reason: str,
    issued_at: Optional[str] = None,
) -> bytes:
    """
    Coordinator → Org: signed per-org trust update. Org keeps these as
    cryptographic proof of how its score evolved.
    """
    payload = {
        "type":         "fl.trust_update.v1",
        "org_id":       str(org_id),
        "round_id":     int(round_id),
        "trust_score":  round(float(new_trust_score), 6),
        "reason":       str(reason),
        "issued_at":    issued_at or datetime.now(timezone.utc).isoformat(),
    }
    return canonical_json(payload)


# ── Challenge tokens ────────────────────────────────────────────────────────

def generate_challenge() -> str:
    """One-shot nonce, hex-encoded. Coordinator binds this to (org_id, round_id)
    and consumes it atomically when a contribution is submitted."""
    return secrets.token_hex(16)
