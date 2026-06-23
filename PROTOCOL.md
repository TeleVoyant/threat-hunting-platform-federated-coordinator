# apt-fl-coordinator wire protocol

Version: **1.0**. This document is the normative reference for independent client
implementations. All four message types are signed with **Ed25519** over **canonical
JSON** (sorted keys, no whitespace, ASCII-escaped). The exact signed bytes MUST be
transmitted and verified as-is — never re-serialised.

```
canonical_json(obj) = json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=True)
```

Each org holds ONE Ed25519 keypair used for both transport (its CA-signed mTLS client
cert wraps the same public key) and message signatures. The coordinator holds its own
keypair; its public key is returned to every org at enrollment.

## Transport

- All calls are HTTPS. Org-facing endpoints (`/fl/rounds/{id}/challenge|contribute|
  global-model`) require **mTLS**: the org presents its CA-signed client cert; the
  coordinator's middleware re-verifies the chain against the federation CA, checks
  expiry + CRL, and maps the cert CN → `org_id`.
- Operator endpoints authenticate with a coordinator-issued JWT (`iss: fl-coordinator`)
  or operator API key — a separate trust domain from org identity.

## Identities & enrollment

`POST /fl/orgs/enroll` (operator) takes the org's Ed25519 **public key PEM** and returns:
`client_cert_pem` (CA-signed, CN = org_id), `ca_cert_pem` (trust anchor),
`coordinator_pub_pem` (to verify coordinator signatures), and a one-time bootstrap
`api_key`. The org keeps its private key; it never leaves the org.

## Message types

### 1. `fl.contribution.v1`  (org → coordinator)
Signed by the **org**, accompanies a model upload.
```json
{ "type":"fl.contribution.v1", "round_id":<int>, "org_id":"<str>",
  "model_sha256":"<hex sha256 of the uploaded model bytes>",
  "num_examples":<int>, "challenge":"<hex nonce from /challenge>",
  "submitted_at":"<ISO-8601 UTC>" }
```

### 2. `fl.global_model.v1`  (coordinator → org)
Signed by the **coordinator**, returned with the aggregated model.
```json
{ "type":"fl.global_model.v1", "round_id":<int>,
  "model_sha256":"<hex sha256 of the global model bytes>",
  "accepted_orgs":["<org_id>", ...], "distributed_at":"<ISO-8601 UTC>" }
```

### 3. `fl.round_announce.v1`  (coordinator → org)
Signed by the **coordinator** when a round is started; an invited org fetches it
from `GET /fl/rounds/{id}/announcement` (mTLS) and verifies the signature to prove
the round was authorised by the coordinator before contributing (no rogue invites).
Emitted only when the federation CA/coordinator keypair is loaded.
```json
{ "type":"fl.round_announce.v1", "round_id":<int>, "epsilon":<float>,
  "num_boost_rounds":<int>, "invited_orgs":["<org_id>", ...],
  "starts_at":"<ISO-8601 UTC>" }
```

### 4. `fl.trust_update.v1`  (coordinator → org)
Signed per-org trust change, returned by `/aggregate`; orgs keep these as proof.
```json
{ "type":"fl.trust_update.v1", "org_id":"<str>", "round_id":<int>,
  "trust_score":<float>, "reason":"<str>", "issued_at":"<ISO-8601 UTC>" }
```

### 5. `fl.leave_request.v1`  (org → coordinator)
Signed by the **org** to request removal from the federation (mutual-ack
handshake, step 1). POSTed to `/fl/orgs/{id}/leave-request`; the coordinator
verifies it against the org's registered public key (so no third party can forge
a leave for another org) and moves the org to `leave_pending` — it is no longer
invited to rounds, but removal is not final until an operator approves.
```json
{ "type":"fl.leave_request.v1", "org_id":"<str>", "reason":"<str>",
  "requested_at":"<ISO-8601 UTC>" }
```

### 6. `fl.removal_confirm.v1`  (coordinator → org)
Signed by the **coordinator** when an operator APPROVES a pending leave
(`POST /fl/orgs/{id}/approve-removal`, step 2 — valid only from `leave_pending`).
The org fetches it from `GET /fl/orgs/{id}/removal-status` and **verifies it
before wiping its local credentials**. Approval also sets the org `revoked` and
regenerates the CRL. (An operator may also `DELETE /fl/orgs/{id}` to force-revoke
a non-requesting org; that emits no confirmation.)
```json
{ "type":"fl.removal_confirm.v1", "org_id":"<str>", "revoked_at":"<ISO-8601 UTC>" }
```

## Contribution flow (the core exchange)

```
org                                           coordinator
 │  GET /fl/rounds/{r}/challenge  (mTLS)  ───▶  issue nonce bound to (org,r), TTL 10m
 │  ◀── { challenge, expires_at }
 │  model = local XGBoost JSON, DP-noised
 │  att = canonical_json(fl.contribution.v1{... model_sha256, challenge, submitted_at})
 │  sig = Ed25519_sign(org_priv, att)
 │  POST /fl/rounds/{r}/contribute  (mTLS)
 │      multipart: attestation=<att utf-8>, signature=<sig hex>, model=<bytes>
 │                                        ───▶  VERIFY (all must pass):
 │                                                1. att parses, type == fl.contribution.v1
 │                                                2. att.org_id == mTLS org
 │                                                3. att.round_id == URL r, round running
 │                                                4. sha256(model) == att.model_sha256
 │                                                5. |now - submitted_at| <= 300s
 │                                                6. consume challenge atomically (replay-safe)
 │                                                7. Ed25519_verify(org_pub, att, sig)
 │  ◀── 202 { contribution_id, accepted:true }   persist model bytes + signed att
```
Rejections: `400` malformed/size, `403` identity/sig/replay, `409` round not running or
org already contributed, `413` model too large.

## Aggregation + distribution

A round has an intake/observation window (`FL_OBSERVATION_HOURS`, default 48h). Aggregation
is operator-triggered AFTER the window and produces a *staged* global model that soaks for a
second window before the operator publishes it. Set the window to 0 for no wait.

```
operator  POST /fl/rounds/{r}/aggregate          (refused 409 until intake window elapses)
              for each accepted contribution:
                  trust-validate (structure + accuracy + sudden-drop) on the public set
                  update + persist org trust; EXCLUDE if trust < 0.3
              enforce ONE feature schema across survivors (else exclude misaligned ones)
              merge survivors by federated bagging, weight = trust x num_examples
              STAGE the merged model as a new version; round -> 'aggregated'
          ◀── 200 { version_id, status:'aggregated', global_model_sha256, accepted_orgs,
                    rejected[], merge{}, staged_until, trust_updates[] }

operator  POST /fl/rounds/{r}/publish            (refused 409 until soak window elapses)
              promote the staged version to 'active' (archive previous active); round 'completed'
          ◀── 200 { version_id, status:'active', model_sha256 }
          (rollback: POST /fl/models/{version}/rollback re-activates a prior version)

org       GET /fl/global-model  (mTLS)           (current active version; per-round at
                                                  /fl/rounds/{r}/global-model)
          ◀── { model_b64, signed_attestation (fl.global_model.v1), signature_hex }
              org MUST verify coordinator signature AND sha256(model)==att.model_sha256
              before loading the model.
```

## Model format

XGBoost-native **JSON** (`booster.save_model("m.json")`). Differential privacy
(Laplace noise on leaf values, ε configurable, default 1.0) is applied client-side
before signing, so the noised bytes are what `model_sha256` covers. The coordinator
merges at the JSON tree level and renumbers tree ids so the global model loads cleanly.

## Versioning

The `type` field carries the version (`*.v1`). Breaking changes bump the suffix; the
coordinator rejects unknown types with `400`. This document's version moves with the
set of supported message types.
