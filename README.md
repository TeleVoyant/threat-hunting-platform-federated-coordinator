# apt-fl-coordinator

A standalone, security-hardened **federated aggregation server** for collaborative
threat-detection models. Multiple threat-hunting platforms train XGBoost locally on
their own telemetry, share only the (differentially-private) **tree structure** — never
raw logs — and this neutral coordinator **combines** those matrices into one global
model and **redistributes** it. No raw security data ever crosses an organisation's
boundary.

It is the cross-organization half of the *Threat Hunting Software for Detecting
Credential-Based Lateral Movement APTs* project, extracted into its own repository so a
neutral consortium can run it independently of any participating org's platform.

> **Trust boundary.** This coordinator is operated by a neutral party. It has its own
> operators, its own JWT secret, its own audit log, and its own CA. An org admin cannot
> see another org's contribution; a coordinator operator cannot see any org's telemetry.

## What it does

```
  Org A platform  ──┐  (1) train locally + DP        (4) fetch global model
  Org B platform  ──┤      sign contribution              verify coordinator sig
  Org C platform  ──┘      submit over mTLS  ──▶  [ apt-fl-coordinator ]  ──▶ redistribute
                                                   (2) verify (nonce, sig,
                                                       hash, freshness)
                                                   (3) trust-validate +
                                                       federated-bagging merge
```

- **Receive** — orgs submit XGBoost models with a signed attestation; the server runs a
  7-step verification (org/round binding, SHA-256 integrity, ±5-min freshness, one-shot
  nonce, Ed25519 signature) before persisting the bytes.
- **Combine** — after the round's intake/observation window, the operator aggregates: the
  server trust-validates every accepted contribution against a public validation set, drops
  low-trust/poisoned ones, enforces a **single feature schema** across survivors (so bagged
  tree split-indices stay aligned), and merges the rest by **federated bagging** (tree
  ensembles concatenated in proportion to trust × data size, capped at 500 trees). The
  result is a **staged** global-model version that soaks under observation.
- **Supply** — after the soak window the operator **publishes** the staged version to active;
  only then is it served (`GET /global-model`), **coordinator-signed**, so an org can prove it
  is authentic and untampered before loading. Versions are tracked (staged → active → archived)
  and the operator can **roll back** to a previous one.

## Security model

| Threat | Defense |
|---|---|
| **MITM / tampering** | mTLS both directions + Ed25519 message signatures + SHA-256 model binding |
| **Replay** | one-shot per-(org, round) nonce, atomically consumed, + ±5-min timestamp freshness |
| **Forged global model** | coordinator signs every global model; clients verify before loading |
| **Impersonation / Sybil** | CA-gated enrollment (operator-approved), one client cert per org, CRL revocation |
| **Model poisoning** | trust manager: structural + accuracy + sudden-drop checks on a public validation set; trust-weighted aggregation; orgs below trust 0.3 excluded |
| **Repudiation** | every contribution's signed attestation is persisted; hash-chained audit log |
| **Data exposure** | only DP-noised tree structures leave an org; the coordinator never sees raw telemetry |
| **DoS / abuse** | max-payload cap, one-accepted-contribution per (org, round), container hardening |

See [PROTOCOL.md](PROTOCOL.md) for the exact wire format and [SECURITY.md](SECURITY.md)
for the threat model and disclosure policy.

## Quickstart (Docker)

```bash
# 1. Operator JWT secret (Docker secret — never committed / never in env)
openssl rand -base64 48 > secrets/fl_jwt_secret

# 2. Operator roster — generate an api_key + hash, put the hash in config/fl_users.yml
cp config/fl_users.example.yml config/fl_users.yml   # then edit api_key_hash

# 3. (optional) public validation set for trust scoring
python examples/gen_validation.py config/validation.svm

# 4. Bootstrap the federation CA + coordinator TLS cert (one time)
docker compose run --rm coordinator \
    python -m coordinator.init_ca --ca-dir /app/data/ca --hostname fl.example.com

# 5. Start it (mTLS-required, read-only, non-root, caps dropped)
docker compose up -d
```

Distribute `data/ca/ca_cert.pem` to participating orgs out-of-band (it is their trust
anchor). Orgs generate an Ed25519 keypair locally and you enroll them with their public
key; enrollment returns their CA-signed client cert + the coordinator's public key.

## Operator console

A self-contained web dashboard at **`/dashboard`** lets an operator run every task —
enroll/block/revoke orgs, start rounds, aggregate, publish, roll back global models, and
read the hash-chained audit trail — **without typing a command**. Sign in with an FL
operator username + API key (from the roster); the session is a JWT in an HttpOnly cookie,
and the pages drive the same `/fl/*` API, so every click is recorded in the audit chain
with the same RBAC. Login/logout are audited too.

## Operator + org API (prefix `/fl`)

| Method | Path | Who | Purpose |
|---|---|---|---|
| POST | `/orgs/enroll` | operator (admin) | register an org, issue its client cert |
| GET | `/orgs` | operator | list orgs + trust scores |
| POST | `/orgs/{id}/block` · `/unblock` · DELETE `/orgs/{id}` | operator/admin | lifecycle / revoke |
| POST | `/rounds/start` | operator | open a round (sets the intake window; emits a signed announcement) |
| GET | `/rounds/active` | org (mTLS) | discover open rounds this org is invited to |
| GET | `/rounds/{id}/announcement` | org (mTLS) | coordinator-signed round announcement to verify |
| GET | `/rounds/{id}/challenge` | org (mTLS) | one-shot nonce |
| POST | `/rounds/{id}/contribute` | org (mTLS) | submit a signed model matrix |
| POST | `/rounds/{id}/aggregate` | operator | (after intake window) trust + schema validate → **stage** a global model |
| POST | `/rounds/{id}/publish` | operator | (after soak window) promote the staged model to **active** |
| GET | `/global-model` | org (mTLS) | download the current **active** coordinator-signed global model |
| GET | `/rounds/{id}/global-model` | org (mTLS) | download a specific published round's model (history) |
| GET | `/models` | operator | global-model version history (staged/active/archived) |
| POST | `/models/{version}/rollback` | operator | re-activate a previous global-model version |
| GET | `/audit` | operator | hash-chained audit trail |

A reference participant client lives in [`client_ref/`](client_ref/fl_client.py).

## Layout

```
flproto/       vendored, self-contained protocol core (attestation, CA, libsvm)
coordinator/   the server: api, store, security/RBAC, mTLS, aggregation, trust, audit,
               dashboard (operator web console) + templates/
client_ref/    reference org client (train -> DP -> sign -> submit -> verify)
tests/         unit + end-to-end (full round) + dashboard — runnable scripts
examples/      validation-set generator + end-to-end walkthrough
```

## Develop / test

```bash
python -m venv venv && . venv/bin/activate
pip install -r requirements.lock.txt
PYTHONPATH=. OMP_NUM_THREADS=1 python tests/test_unit.py
PYTHONPATH=. OMP_NUM_THREADS=1 python tests/test_e2e.py
```

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). The wire protocol is
versioned ([PROTOCOL.md](PROTOCOL.md)) so independent client implementations can conform.

## License

[Apache-2.0](LICENSE).
