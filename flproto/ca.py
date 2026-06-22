# federated/ca.py
"""
Federation Certificate Authority for mTLS.

Design choices:
  - Self-signed root CA (10-year validity by default)
  - TLS PKI (root CA + coordinator server cert) uses ECDSA P-256 so the
    operator dashboard is reachable from a normal web browser — browsers do
    NOT support Ed25519 server certificates. OpenSSL/Python clients accept
    ECDSA fine, so org mTLS is unaffected.
  - Org CLIENT certs wrap each org's Ed25519 key, so one org keypair still
    serves both mTLS client auth AND message-level signed contributions.
  - The coordinator's MODEL-signing key is a SEPARATE Ed25519 key
    (coordinator_signing_key.pem); coordinator_pub_pem is that key, so orgs
    keep verifying coordinator-signed global models with Ed25519 as before.
  - 1-year client cert lifetime (configurable). Renewal via re-enrollment.
  - CRL on disk (regenerated when an org is revoked) — coordinator reloads
    on startup; for hot revocation use the existing /fl/orgs/{id}/block path

Production hardening notes (Chapter 8):
  - CA private key should live on a HSM or air-gapped host
  - Move to OCSP for real-time revocation
  - Consider intermediate CAs so the root key only signs intermediates
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID

from flproto.attestation import (
    generate_keypair, private_key_from_pem, private_key_to_pem,
    public_key_from_pem, public_key_to_pem,
)


# ── Filenames within the CA directory ──────────────────────────────────────

CA_KEY_FILE         = "ca_key.pem"
CA_CERT_FILE        = "ca_cert.pem"
COORDINATOR_KEY_FILE  = "coordinator_key.pem"             # ECDSA P-256 TLS key
COORDINATOR_CERT_FILE = "coordinator_cert.pem"            # ECDSA P-256 TLS cert
COORDINATOR_SIGNING_KEY_FILE = "coordinator_signing_key.pem"  # Ed25519 model-signing key
CRL_FILE            = "crl.pem"


# ── Signing helpers ─────────────────────────────────────────────────────────

_AnyPrivateKey = Union[Ed25519PrivateKey, ec.EllipticCurvePrivateKey]


def _ca_sign_algorithm(ca_priv):
    """Hash to pass to CertificateBuilder.sign()/CRLBuilder.sign() for the CA's
    key type: Ed25519 requires None; ECDSA (and RSA) require an explicit hash."""
    return None if isinstance(ca_priv, Ed25519PrivateKey) else hashes.SHA256()


def _load_any_private_key(pem: bytes):
    """Load a PEM private key of any supported type (ECDSA or Ed25519)."""
    return load_pem_private_key(pem, password=None)


# ── CA initialisation ─────────────────────────────────────────────────────

def init_ca(
    ca_dir: str,
    *,
    common_name: str = "APT Platform Federation Root CA",
    validity_days: int = 3650,           # 10 years
    coordinator_hostname: str = "localhost",
) -> dict:
    """
    Create a new federation root CA + the coordinator's server cert + signing key.

    The CA and the coordinator's server cert are ECDSA P-256 so the operator
    dashboard loads in a browser. The coordinator's MODEL-signing key is a
    separate Ed25519 key; its public half is returned as coordinator_pub_pem
    (what orgs use to verify coordinator-signed global models).

    Returns paths to all generated files. Refuses if a CA already exists
    in ca_dir (so this can't accidentally rotate the root and invalidate
    every org's trust).
    """
    cd = Path(ca_dir)
    cd.mkdir(parents=True, exist_ok=True)
    if (cd / CA_KEY_FILE).exists():
        raise FileExistsError(
            f"CA already exists at {cd / CA_KEY_FILE}. "
            "Refusing to overwrite (would invalidate all org enrollments)."
        )

    # ── Root CA keypair + self-signed cert (ECDSA P-256 for browser TLS) ────
    ca_priv = ec.generate_private_key(ec.SECP256R1())
    ca_pub = ca_priv.public_key()
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "APT Platform Federation"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))     # tiny back-date for clock skew
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_pub),
            critical=False,
        )
        .sign(private_key=ca_priv, algorithm=_ca_sign_algorithm(ca_priv))
    )

    (cd / CA_KEY_FILE).write_bytes(private_key_to_pem(ca_priv))
    (cd / CA_KEY_FILE).chmod(0o600)
    (cd / CA_CERT_FILE).write_bytes(
        ca_cert.public_bytes(serialization.Encoding.PEM)
    )

    # ── Coordinator TLS server keypair + cert (ECDSA P-256, signed by CA) ───
    tls_priv = ec.generate_private_key(ec.SECP256R1())
    tls_pub = tls_priv.public_key()
    coord_cert = issue_server_cert(
        ca_priv=ca_priv, ca_cert=ca_cert,
        server_pub=tls_pub, hostname=coordinator_hostname,
    )
    (cd / COORDINATOR_KEY_FILE).write_bytes(private_key_to_pem(tls_priv))
    (cd / COORDINATOR_KEY_FILE).chmod(0o600)
    (cd / COORDINATOR_CERT_FILE).write_bytes(
        coord_cert.public_bytes(serialization.Encoding.PEM)
    )

    # ── Coordinator model-signing keypair (Ed25519, separate from TLS) ──────
    # Orgs verify coordinator-signed global models + round announcements with
    # this key's public half (coordinator_pub_pem). Kept Ed25519 because the
    # attestation signing primitives are Ed25519.
    sign_priv, sign_pub = generate_keypair()
    (cd / COORDINATOR_SIGNING_KEY_FILE).write_bytes(private_key_to_pem(sign_priv))
    (cd / COORDINATOR_SIGNING_KEY_FILE).chmod(0o600)

    # Empty CRL to start
    crl = build_crl(ca_priv, ca_cert, revoked_serials=[])
    (cd / CRL_FILE).write_bytes(crl.public_bytes(serialization.Encoding.PEM))

    return {
        "ca_dir":                  str(cd),
        "ca_cert":                 str(cd / CA_CERT_FILE),
        "ca_key":                  str(cd / CA_KEY_FILE),
        "coordinator_cert":        str(cd / COORDINATOR_CERT_FILE),
        "coordinator_key":         str(cd / COORDINATOR_KEY_FILE),
        "coordinator_signing_key": str(cd / COORDINATOR_SIGNING_KEY_FILE),
        "crl":                     str(cd / CRL_FILE),
        "coordinator_pub_pem":     public_key_to_pem(sign_pub).decode(),
    }


# ── CA load helpers ───────────────────────────────────────────────────────

def load_ca(ca_dir: str) -> tuple[_AnyPrivateKey, x509.Certificate]:
    cd = Path(ca_dir)
    priv = _load_any_private_key((cd / CA_KEY_FILE).read_bytes())
    cert = x509.load_pem_x509_certificate((cd / CA_CERT_FILE).read_bytes())
    return priv, cert


def load_coordinator_keypair(
    ca_dir: str,
) -> tuple[Ed25519PrivateKey, x509.Certificate]:
    """Return the coordinator's Ed25519 MODEL-SIGNING key + its (ECDSA) TLS cert.

    The signing key (coordinator_signing_key.pem) is what att_sign() uses and
    what coordinator_pub_pem exposes. The TLS key (coordinator_key.pem) is ECDSA
    and consumed directly by uvicorn, never here. Falls back to the legacy layout
    (Ed25519 coordinator_key.pem doubling as the signing key) for old CA dirs.
    """
    cd = Path(ca_dir)
    signing_file = cd / COORDINATOR_SIGNING_KEY_FILE
    if not signing_file.exists():
        signing_file = cd / COORDINATOR_KEY_FILE     # legacy pre-ECDSA-TLS CA
    priv = private_key_from_pem(signing_file.read_bytes())
    cert = x509.load_pem_x509_certificate((cd / COORDINATOR_CERT_FILE).read_bytes())
    return priv, cert


# ── Cert issuance ──────────────────────────────────────────────────────────

def issue_client_cert(
    *,
    ca_priv: _AnyPrivateKey,
    ca_cert: x509.Certificate,
    client_pub: Ed25519PublicKey,
    org_id: str,
    display_name: Optional[str] = None,
    validity_days: int = 365,
) -> x509.Certificate:
    """
    Sign a client certificate for one organisation.

    The CommonName encodes the org_id — coordinator extracts this from the
    presented client cert during mTLS handshake to identify the org without
    needing a separate API key. The org's key stays Ed25519 (it doubles as the
    org's contribution-signing key); the CA signs it with its own (ECDSA) key.
    """
    now = datetime.now(timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, org_id),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, display_name or org_id),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "fl-client"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(client_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(client_pub),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .sign(private_key=ca_priv, algorithm=_ca_sign_algorithm(ca_priv))
    )
    return cert


def issue_server_cert(
    *,
    ca_priv: _AnyPrivateKey,
    ca_cert: x509.Certificate,
    server_pub: ec.EllipticCurvePublicKey,
    hostname: str,
    validity_days: int = 365,
) -> x509.Certificate:
    """Server cert for the coordinator (ECDSA P-256). SAN includes the hostname."""
    now = datetime.now(timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "fl-coordinator"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .sign(private_key=ca_priv, algorithm=_ca_sign_algorithm(ca_priv))
    )
    return cert


# ── Verification ───────────────────────────────────────────────────────────

def verify_cert_signed_by_ca(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """
    Verify cert was signed by ca_cert. Does NOT check expiry, revocation,
    or chain — caller is responsible for those (we check expiry separately).
    Handles both ECDSA (TLS PKI) and Ed25519 CA keys.
    """
    pub = ca_cert.public_key()
    try:
        if isinstance(pub, Ed25519PublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        else:
            return False
        return True
    except Exception:
        return False


def cert_org_id(cert: x509.Certificate) -> Optional[str]:
    """Extract org_id from the CommonName of a client cert."""
    try:
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, AttributeError):
        return None


def is_cert_expired(cert: x509.Certificate, now: Optional[datetime] = None) -> bool:
    now = now or datetime.now(timezone.utc)
    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    return now >= not_after or now < not_before


# ── CRL (Certificate Revocation List) ─────────────────────────────────────

def build_crl(
    ca_priv: _AnyPrivateKey,
    ca_cert: x509.Certificate,
    *,
    revoked_serials: list[int],
    validity_days: int = 30,
) -> x509.CertificateRevocationList:
    """
    Build a fresh CRL listing the given serial numbers as revoked.
    Coordinator regenerates this whenever an org is revoked, then reloads
    from disk on the next request cycle.
    """
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now - timedelta(minutes=1))
        .next_update(now + timedelta(days=validity_days))
    )
    for serial in revoked_serials:
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(now)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)
    return builder.sign(private_key=ca_priv, algorithm=_ca_sign_algorithm(ca_priv))


def load_crl(ca_dir: str) -> x509.CertificateRevocationList:
    return x509.load_pem_x509_crl((Path(ca_dir) / CRL_FILE).read_bytes())


def is_revoked(crl: x509.CertificateRevocationList, serial: int) -> bool:
    return crl.get_revoked_certificate_by_serial_number(serial) is not None


# ── Cert serialisation helpers ─────────────────────────────────────────────

def cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def cert_from_pem(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem)
