# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/) and the project aims to follow
semantic versioning. The wire protocol is versioned separately (see PROTOCOL.md).

## [Unreleased]

### Added
- **Operator web console** (`/dashboard`, `coordinator/dashboard.py` + `coordinator/templates/`).
  A self-contained Jinja2 + Alpine dashboard (no build step) where an operator runs every
  task from the browser — enroll/block/revoke orgs, start rounds, aggregate, publish, roll
  back global models, and read the audit trail — with **no commands**. Login issues a JWT in
  an HttpOnly cookie; the pages' `fetch` calls hit the existing `/fl/*` endpoints (cookie
  auth added to `get_fl_user`), so the console reuses the same RBAC and the same hash-chained
  audit logging as the API. Operator login/logout are themselves audited.
- **Observation windows + versioned global models with publish/rollback.** A round
  now has an intake/observation window (`FL_OBSERVATION_HOURS`, default 48h, per-round
  override): `aggregate` is refused until it elapses and produces a **staged** global
  model that soaks for a second window; the operator then `POST /rounds/{id}/publish`
  promotes it to **active** (archiving the previous active version). Global models are
  versioned (staged → active → archived) with `GET /models` history, `GET /global-model`
  serving the current active version to orgs, and `POST /models/{version}/rollback`.
  Set `FL_OBSERVATION_HOURS=0` for no wait (demos).
- **Org-facing round discovery** — `GET /fl/rounds/active` (mTLS) lists open rounds an
  org is invited to, so participant clients can find rounds without out-of-band coordination.
- **Feature-schema consistency gate at aggregation** — every matrix bagged into
  the global model must share one feature space (same `feature_names` / order, or
  `num_feature`). Contributions whose schema differs from the heaviest survivor's
  are excluded (reported + audited), and `merge_xgboost_models` refuses a mixed
  set outright. Prevents a silently-corrupt global model where one org's tree
  split indices reference misaligned features.
- **Signed round announcements wired** — `POST /rounds/start` now emits a
  coordinator-signed `fl.round_announce.v1`; invited orgs fetch + verify it at
  `GET /rounds/{id}/announcement` (mTLS) to confirm a round is authentic before
  contributing (defends against rogue round invites).
- **`FL_REQUIRE_MTLS`** — when set, org endpoints accept verified mTLS identity
  only and refuse the `X-FL-API-Key` bootstrap fallback (production hardening).
- **`FL_MAX_NUM_EXAMPLES`** — caps a contribution's self-reported `num_examples`
  before it becomes aggregation weight, so one org cannot inflate its share of
  the merged ensemble.

### Changed
- The sudden-drop poisoning baseline (per-org last accuracy) is now **persisted**
  in the `orgs` table, so the heuristic survives a coordinator restart.

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
