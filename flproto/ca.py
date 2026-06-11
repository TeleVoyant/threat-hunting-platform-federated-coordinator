# federated/ca.py
"""
Federation Certificate Authority for mTLS.

Design choices:
  - Self-signed root CA (10-year validity by default)
  - Ed25519 keys throughout (CA + clients + coordinator) — same algorithm
    as the attestation signatures, so each org has ONE keypair that serves
    both transport (mTLS) AND message-level (signed contributions)
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
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.x509.oid import NameOID

from flproto.attestation import (
    generate_keypair, private_key_from_pem, private_key_to_pem,
    public_key_from_pem, public_key_to_pem,
)


# ── Filenames within the CA directory ──────────────────────────────────────

CA_KEY_FILE         = "ca_key.pem"
CA_CERT_FILE        = "ca_cert.pem"
COORDINATOR_KEY_FILE  = "coordinator_key.pem"
COORDINATOR_CERT_FILE = "coordinator_cert.pem"
CRL_FILE            = "crl.pem"


# ── CA initialisation ─────────────────────────────────────────────────────

def init_ca(
    ca_dir: str,
    *,
    common_name: str = "APT Platform Federation Root CA",
    validity_days: int = 3650,           # 10 years
    coordinator_hostname: str = "localhost",
) -> dict:
    """
    Create a new federation root CA + the coordinator's server cert.

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

    # ── Root CA keypair + self-signed cert ─────────────────────────────────
    ca_priv, ca_pub = generate_keypair()
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
        .sign(private_key=ca_priv, algorithm=None)   # Ed25519: algorithm must be None
    )

    (cd / CA_KEY_FILE).write_bytes(private_key_to_pem(ca_priv))
    (cd / CA_KEY_FILE).chmod(0o600)
    (cd / CA_CERT_FILE).write_bytes(
        ca_cert.public_bytes(serialization.Encoding.PEM)
    )

    # ── Coordinator's server keypair + cert (signed by root CA) ───────────
    coord_priv, coord_pub = generate_keypair()
    coord_cert = issue_server_cert(
        ca_priv=ca_priv, ca_cert=ca_cert,
        server_pub=coord_pub, hostname=coordinator_hostname,
    )
    (cd / COORDINATOR_KEY_FILE).write_bytes(private_key_to_pem(coord_priv))
    (cd / COORDINATOR_KEY_FILE).chmod(0o600)
    (cd / COORDINATOR_CERT_FILE).write_bytes(
        coord_cert.public_bytes(serialization.Encoding.PEM)
    )

    # Empty CRL to start
    crl = build_crl(ca_priv, ca_cert, revoked_serials=[])
    (cd / CRL_FILE).write_bytes(crl.public_bytes(serialization.Encoding.PEM))

    return {
        "ca_dir":               str(cd),
        "ca_cert":              str(cd / CA_CERT_FILE),
        "ca_key":               str(cd / CA_KEY_FILE),
        "coordinator_cert":     str(cd / COORDINATOR_CERT_FILE),
        "coordinator_key":      str(cd / COORDINATOR_KEY_FILE),
        "crl":                  str(cd / CRL_FILE),
        "coordinator_pub_pem":  public_key_to_pem(coord_pub).decode(),
    }


# ── CA load helpers ───────────────────────────────────────────────────────

def load_ca(ca_dir: str) -> tuple[Ed25519PrivateKey, x509.Certificate]:
    cd = Path(ca_dir)
    priv = private_key_from_pem((cd / CA_KEY_FILE).read_bytes())
    cert = x509.load_pem_x509_certificate((cd / CA_CERT_FILE).read_bytes())
    return priv, cert


def load_coordinator_keypair(
    ca_dir: str,
) -> tuple[Ed25519PrivateKey, x509.Certificate]:
    cd = Path(ca_dir)
    priv = private_key_from_pem((cd / COORDINATOR_KEY_FILE).read_bytes())
    cert = x509.load_pem_x509_certificate((cd / COORDINATOR_CERT_FILE).read_bytes())
    return priv, cert


# ── Cert issuance ──────────────────────────────────────────────────────────

def issue_client_cert(
    *,
    ca_priv: Ed25519PrivateKey,
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
    needing a separate API key.
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
        .sign(private_key=ca_priv, algorithm=None)
    )
    return cert


def issue_server_cert(
    *,
    ca_priv: Ed25519PrivateKey,
    ca_cert: x509.Certificate,
    server_pub: Ed25519PublicKey,
    hostname: str,
    validity_days: int = 365,
) -> x509.Certificate:
    """Server cert for the coordinator. SAN includes the hostname."""
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
        .sign(private_key=ca_priv, algorithm=None)
    )
    return cert


# ── Verification ───────────────────────────────────────────────────────────

def verify_cert_signed_by_ca(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """
    Verify cert was signed by ca_cert. Does NOT check expiry, revocation,
    or chain — caller is responsible for those (we check expiry separately).
    """
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
        )
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
    ca_priv: Ed25519PrivateKey,
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
    return builder.sign(private_key=ca_priv, algorithm=None)


def load_crl(ca_dir: str) -> x509.CertificateRevocationList:
    return x509.load_pem_x509_crl((Path(ca_dir) / CRL_FILE).read_bytes())


def is_revoked(crl: x509.CertificateRevocationList, serial: int) -> bool:
    return crl.get_revoked_certificate_by_serial_number(serial) is not None


# ── Cert serialisation helpers ─────────────────────────────────────────────

def cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def cert_from_pem(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem)
