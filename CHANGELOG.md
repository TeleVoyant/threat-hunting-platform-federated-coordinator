# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and the project aims to follow
semantic versioning. The wire protocol is versioned separately (see PROTOCOL.md).

## [1.0.0] — 2026-06-03

First standalone release, extracted from the Threat Hunting Platform monorepo into an
independently-deployable, Apache-2.0 server.

### Added
- REST matrix-exchange API: org enrollment (CA-signed client certs), round lifecycle,
  one-shot challenge nonces, signed contribution upload with 7-step verification,
  on-demand aggregation, and coordinator-signed global-model download.
- **REST-native federated bagging** (`coordinator/aggregation.py`) — combines accepted
  XGBoost tree ensembles weighted by trust × data size, capped at 500 trees, with no
  Flower/gRPC dependency.
- **Persisted trust manager** (`coordinator/trust.py`) — structural + accuracy +
  sudden-drop poisoning checks against a public validation set; trust-weighted
  aggregation; orgs below trust 0.3 excluded.
- **Persistence of submitted model bytes** + per-(org, round) de-duplication and a
  max-payload guard.
- Vendored, self-contained protocol core (`flproto/`: Ed25519 attestations, federation
  CA + CRL, libsvm loader) — zero monorepo dependencies.
- Reference participant client (`client_ref/`) with client-side differential privacy.
- Hardened Docker image + compose (read-only, non-root, caps dropped, mTLS, Docker
  secrets), wire-protocol spec, threat model, and unit + end-to-end test suites.

### Wire protocol
- `fl.contribution.v1`, `fl.global_model.v1`, `fl.round_announce.v1`,
  `fl.trust_update.v1` (see PROTOCOL.md v1.0).
