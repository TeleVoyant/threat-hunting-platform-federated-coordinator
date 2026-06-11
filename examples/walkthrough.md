# End-to-end walkthrough

A full federation round: bootstrap → enroll two orgs → each contributes a signed model
→ aggregate → fetch + verify the global model. Assumes `docker compose up -d` per the
README, with the CA already initialised and an operator API key whose hash is in
`config/fl_users.yml`. `COORD=https://fl.example.com:8889`.

> Org-facing calls use mTLS. With `curl`, present the org's cert/key and pin the CA:
> `--cert org.crt --key org.key --cacert ca_cert.pem`. The reference Python client
> ([`client_ref/fl_client.py`](../client_ref/fl_client.py)) wraps all of this.

## 1. Enroll an org (operator)

Each org first generates its own Ed25519 keypair locally and sends you the **public** PEM.

```bash
curl -s $COORD/fl/orgs/enroll \
  -H "X-FL-API-Key: $OPERATOR_KEY" -H "Content-Type: application/json" \
  -d '{"org_id":"udom","display_name":"UDOM","public_key_pem":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"}'
# -> { client_cert_pem, ca_cert_pem, coordinator_pub_pem, api_key, ... }
```

The org saves `client_cert_pem` (its mTLS identity), `ca_cert_pem` (trust anchor), and
`coordinator_pub_pem` (to verify the global model later).

## 2. Start a round (operator)

```bash
curl -s $COORD/fl/rounds/start -H "X-FL-API-Key: $OPERATOR_KEY" \
  -H "Content-Type: application/json" -d '{"min_clients":2}'
# -> { round_id: 1, status: "running", ... }
```

## 3. Contribute (each org, mTLS) — via the reference client

```python
from flproto.attestation import generate_keypair, private_key_to_pem
from client_ref.fl_client import FLClient, train_local_model

model_bytes, n = train_local_model("my_local_data.svm", epsilon=1.0)   # DP applied
c = FLClient(base_url="https://fl.example.com:8889", org_id="udom",
             org_private_key_pem=open("udom_key.pem","rb").read(),
             client_cert="udom.crt", client_key="udom_key.pem",
             ca_cert="ca_cert.pem",
             coordinator_public_key_pem=open("coordinator_pub.pem","rb").read())
print(c.submit_contribution(round_id=1, model_bytes=model_bytes, num_examples=n))
# the client fetches a fresh nonce, signs the attestation, and uploads over mTLS
```

Under the hood this is: `GET /fl/rounds/1/challenge` → sign `fl.contribution.v1` →
`POST /fl/rounds/1/contribute` (multipart: attestation, signature, model).

## 4. Aggregate (operator)

```bash
curl -s $COORD/fl/rounds/1/aggregate -X POST -H "X-FL-API-Key: $OPERATOR_KEY"
# -> { status:"completed", global_model_sha256, accepted_orgs:["udom","bank-x"],
#      rejected:[], merge:{total_trees:..}, trust_updates:[signed ...] }
```

The coordinator trust-validates each contribution against its public validation set,
drops any below trust 0.3, and merges the survivors by federated bagging.

## 5. Fetch + verify the global model (each org)

```python
global_model = c.fetch_global_model(round_id=1)   # raises if signature/hash fail
open("global_round1.json","wb").write(global_model)
# load into your detector:  booster.load_model(bytearray(global_model))
```

`fetch_global_model` verifies the coordinator's Ed25519 signature over the
`fl.global_model.v1` attestation **and** that `sha256(model)` matches before returning —
so a tampered or forged model is rejected, not loaded.

## 6. Inspect the audit trail (operator)

```bash
curl -s $COORD/fl/audit -H "X-FL-API-Key: $OPERATOR_KEY"
# hash-chained: enroll, round.start, contribution.accepted, round.aggregated, ...
```
