# federated/mtls_middleware.py
"""
ASGI middleware that turns the TLS-handshake peer certificate into an
authenticated org_id on `request.state.mtls_org_id`.

Production flow (real TLS):
    Client                   uvicorn (TLS)             this middleware
       │── ClientHello ─────────▶│
       │  + client cert          │── verifies cert chain against CA bundle
       │                         │   (configured via --ssl-ca-certs +
       │                         │    --ssl-cert-reqs 2)
       │◀──────── 200 OK ────────│── peer cert reachable in ASGI scope
                                 │── this middleware:
                                 │     1. Extract cert from scope
                                 │     2. Re-verify chain against our CA
                                 │     3. Check CRL (revoked orgs)
                                 │     4. Check expiry
                                 │     5. Set request.state.mtls_org_id = cert CN

Why re-verify on top of uvicorn's check?
   uvicorn validates the chain at handshake time, but we still want our
   OWN explicit checks because (a) our CA is the only trust anchor — we
   don't want any other CA chain accidentally trusted; (b) we own the
   CRL; (c) explicit checks are easier to test and audit.

Dev / test fallback:
   When FL_DEV_ALLOW_HEADER_MTLS=1 is set, the middleware ALSO accepts an
   X-Dev-Mtls-Org-Id header that injects an org_id directly. This makes
   the test-suite work without spinning up real TLS. NEVER set this env
   var in production — anyone who can hit the API could spoof identity.
"""

import os
import ssl
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from flproto.ca import (
    cert_org_id, is_cert_expired, is_revoked, verify_cert_signed_by_ca,
)
from coordinator.logging import get_logger

logger = get_logger("federated.mtls_middleware")


_DEV_HEADER_NAME = "x-dev-mtls-org-id"


def _dev_header_allowed() -> bool:
    """Dev escape hatch — only honoured when env var is explicitly set."""
    return os.environ.get("FL_DEV_ALLOW_HEADER_MTLS", "0") == "1"


def _extract_cert_from_scope(request: Request) -> Optional[x509.Certificate]:
    """
    Try every place uvicorn might stash the verified peer cert. Returns
    None when there's no TLS in front (i.e., dev / non-TLS test).
    """
    # ASGI TLS extension (uvicorn 0.18+ in some configurations)
    ext = request.scope.get("extensions", {}) or {}
    tls = ext.get("tls", {}) or {}
    cert_der = tls.get("client_cert_chain") or tls.get("peer_cert")
    if cert_der and isinstance(cert_der, list) and cert_der:
        cert_der = cert_der[0]

    if cert_der:
        try:
            if isinstance(cert_der, (bytes, bytearray)):
                # DER form
                return x509.load_der_x509_certificate(bytes(cert_der))
            if isinstance(cert_der, str):
                return x509.load_pem_x509_certificate(cert_der.encode())
        except Exception as e:
            logger.warning("Could not parse peer cert from scope", error=str(e))

    # Fallback: dig into the underlying asyncio transport (uvicorn's standard way)
    # This works when uvicorn is run with --ssl-cert-reqs 2.
    transport = request.scope.get("transport")
    if transport is not None:
        try:
            ssl_obj = transport.get_extra_info("ssl_object")
            if ssl_obj is not None:
                # getpeercert(binary_form=True) returns DER
                der = ssl_obj.getpeercert(binary_form=True)
                if der:
                    return x509.load_der_x509_certificate(der)
        except Exception as e:
            logger.debug("No peer cert via transport", error=str(e))

    return None


class MTLSMiddleware(BaseHTTPMiddleware):
    """
    Sets request.state.mtls_org_id when a valid peer cert is present.

    Behaviour:
      - Routes that REQUIRE org auth use the get_authenticated_org_id
        dependency in coordinator_api.py — that dependency reads
        request.state.mtls_org_id first, falls back to API key. So this
        middleware just enriches the request; route-level dependencies
        decide whether mTLS is acceptable for that endpoint.
      - Cert chain + expiry + CRL are validated HERE. If cert is invalid
        we DO NOT set mtls_org_id (the dependency will fall back / 401).

    The middleware itself never returns errors — invalid certs are silently
    ignored so that endpoints which permit API-key bootstrap still work.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        org_id = self._extract_verified_org_id(request)
        if org_id:
            request.state.mtls_org_id = org_id
        return await call_next(request)

    def _extract_verified_org_id(self, request: Request) -> Optional[str]:
        # ── Dev path: header-injected identity (test-only) ──────────────────
        if _dev_header_allowed():
            hdr = request.headers.get(_DEV_HEADER_NAME)
            if hdr:
                logger.warning(
                    "DEV mTLS header accepted — never enable this in production",
                    org_id=hdr,
                )
                return hdr

        # ── Real TLS path ───────────────────────────────────────────────────
        cert = _extract_cert_from_scope(request)
        if cert is None:
            return None

        ca_cert = getattr(request.app.state, "fl_ca_cert", None)
        if ca_cert is None:
            logger.warning("Peer cert present but no CA loaded — ignoring")
            return None

        # 1. Signed by our CA
        if not verify_cert_signed_by_ca(cert, ca_cert):
            logger.warning("Peer cert NOT signed by federation CA — ignoring")
            return None

        # 2. Not expired
        if is_cert_expired(cert):
            logger.warning("Peer cert expired — ignoring",
                            not_after=str(cert.not_valid_after_utc))
            return None

        # 3. Not revoked (CRL check — CRL loaded into app.state if available)
        crl = getattr(request.app.state, "fl_crl", None)
        if crl is not None and is_revoked(crl, cert.serial_number):
            logger.warning("Peer cert serial is in CRL — ignoring",
                            serial=str(cert.serial_number))
            return None

        # 4. Extract org_id from cert CN
        org_id = cert_org_id(cert)
        if not org_id:
            logger.warning("Peer cert has no CN — ignoring")
            return None

        # 5. Verify the org actually exists + is active
        store = getattr(request.app.state, "coordinator_store", None)
        if store:
            org = store.get_org(org_id)
            if not org or org["status"] != "active":
                logger.warning("Cert CN doesn't match an active org",
                                org_id=org_id, status=org["status"] if org else "missing")
                return None

        return org_id
