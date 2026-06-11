# Security policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for an
exploitable flaw. Email the maintainers (see repository metadata) with:

- a description and impact assessment,
- reproduction steps or a proof of concept,
- affected version / commit.

We aim to acknowledge within 72 hours and to coordinate a fix and disclosure timeline
with you. Credit is given to reporters who wish to be named.

## Threat model (what this server defends against)

The coordinator is a **neutral aggregation point** for mutually-distrusting
organisations. It assumes a hostile network and partially-malicious participants.

| Threat | Mitigation |
|---|---|
| Eavesdropping / MITM | mTLS both directions; message-level Ed25519 signatures; SHA-256 binds the signature to the exact model bytes |
| Replay | one-shot nonce per (org, round), atomically consumed; ±5-minute timestamp freshness |
| Forged / tampered global model | coordinator-signed global model; client verifies signature + hash before loading |
| Org impersonation / Sybil | CA-gated, operator-approved enrollment; one client cert per org; CRL revocation; cert CN bound to a registered active org |
| Model poisoning | trust manager (structural + accuracy + sudden-drop checks on a public validation set); trust-weighted aggregation; orgs below trust 0.3 excluded |
| Repudiation | every accepted contribution's signed attestation is persisted; hash-chained, tamper-evident audit log |
| Raw-data exposure | only differentially-private tree structures leave an org; the coordinator never receives raw telemetry |
| Resource exhaustion | max-payload cap; one accepted contribution per (org, round); container resource limits |
| Host compromise blast radius | read-only rootfs, non-root user, all Linux capabilities dropped, `no-new-privileges`, isolated network |

## Explicitly out of scope / operator responsibilities

- **CA private key custody.** The federation root key signs all trust. Production
  deployments SHOULD keep it on an HSM or air-gapped host; this repo stores it on disk
  for ease of bootstrap.
- **Validation-set quality.** Poisoning defense is only as good as the public validation
  set the operator supplies; an unrepresentative set weakens it (or, if unset, the server
  falls back to structure-only trust).
- **`FL_DEV_ALLOW_HEADER_MTLS`** must NEVER be set in production — it bypasses mTLS and
  lets any caller assert an org identity. It exists only for tests.
- Revocation here is CRL-on-disk reloaded periodically; sub-second revocation would
  require OCSP.
