# flproto/seal_box.py  (byte-identical to threat-hunting-platform/federated/seal_box.py)
"""
Anonymous sealed-box encryption (libsodium crypto_box_seal equivalent), built on
`cryptography` only (no PyNaCl). Used to encrypt the enrollment package to the
org's X25519 public key so it can be delivered over ANY channel: only the holder
of the matching X25519 private key can open it.

Construction (ephemeral-static ECIES, authenticated):
  seal:   eph = X25519.generate()
          shared = eph.exchange(recipient_pub)
          key = HKDF-SHA256(shared, salt = eph_pub_raw || recipient_pub_raw,
                            info = "fl.enroll.seal.v1")        # binds both keys
          ct  = ChaCha20Poly1305(key).encrypt(nonce=0*12, plaintext, aad=eph_pub_raw)
          wire = base64( eph_pub_raw(32) || ct )
  unseal: shared = recipient_priv.exchange(eph_pub); recompute key; decrypt.

A FRESH ephemeral key per seal makes the derived key single-use, so a fixed
all-zero nonce is safe. The recipient pubkey is mixed into the KDF salt so a
ciphertext can't be re-bound to a different recipient; the ephemeral pubkey is
the AEAD associated data so it can't be swapped.
"""

import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_INFO = b"fl.enroll.seal.v1"
_NONCE = b"\x00" * 12   # safe: the derived key is single-use (fresh ephemeral per seal)


# ── X25519 keypair lifecycle ────────────────────────────────────────────────

def generate_x25519_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    priv = X25519PrivateKey.generate()
    return priv, priv.public_key()


def x25519_public_to_pem(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def x25519_private_to_pem(priv: X25519PrivateKey) -> bytes:
    """Unencrypted PEM — caller stores it encrypted at rest (Fernet)."""
    return priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())


def x25519_public_from_pem(pem: bytes) -> X25519PublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, X25519PublicKey):
        raise ValueError("Not an X25519 public key")
    return key


def x25519_private_from_pem(pem: bytes) -> X25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, X25519PrivateKey):
        raise ValueError("Not an X25519 private key")
    return key


# ── Seal / unseal ───────────────────────────────────────────────────────────

def _raw_pub(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _derive(shared: bytes, eph_pub_raw: bytes, recip_pub_raw: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32,
               salt=eph_pub_raw + recip_pub_raw, info=_INFO).derive(shared)


def seal(recipient_pub_pem, plaintext: bytes) -> str:
    """Encrypt `plaintext` to a recipient X25519 public key (PEM bytes or str).
    Returns base64 of (ephemeral_pub_raw(32) || ciphertext)."""
    if isinstance(recipient_pub_pem, str):
        recipient_pub_pem = recipient_pub_pem.encode()
    recip = x25519_public_from_pem(recipient_pub_pem)
    eph = X25519PrivateKey.generate()
    eph_pub_raw = _raw_pub(eph.public_key())
    key = _derive(eph.exchange(recip), eph_pub_raw, _raw_pub(recip))
    ct = ChaCha20Poly1305(key).encrypt(_NONCE, plaintext, eph_pub_raw)
    return base64.b64encode(eph_pub_raw + ct).decode()


def unseal(recipient_priv, sealed_b64: str) -> bytes:
    """Decrypt a sealed blob with the recipient's X25519 private key (PEM bytes/str
    or an X25519PrivateKey). Raises on any tampering or wrong key."""
    if isinstance(recipient_priv, (bytes, str)):
        pem = recipient_priv.encode() if isinstance(recipient_priv, str) else recipient_priv
        recipient_priv = x25519_private_from_pem(pem)
    raw = base64.b64decode(sealed_b64)
    eph_pub_raw, ct = raw[:32], raw[32:]
    eph_pub = X25519PublicKey.from_public_bytes(eph_pub_raw)
    key = _derive(recipient_priv.exchange(eph_pub), eph_pub_raw,
                  _raw_pub(recipient_priv.public_key()))
    return ChaCha20Poly1305(key).decrypt(_NONCE, ct, eph_pub_raw)
