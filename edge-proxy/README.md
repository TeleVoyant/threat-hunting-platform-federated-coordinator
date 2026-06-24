# Host nginx — central reverse proxy for the server

**HOST-installed** nginx (apt / systemd, NOT a container) is the single ingress
for the whole Contabo box (`13.140.173.164`). Backends (the dockerized FL
coordinator + future apps) bind to **`127.0.0.1` only**; nginx is the sole
process listening on public ports.

| Public port | Purpose | TLS |
|-------------|---------|-----|
| `:80`   | redirect to HTTPS (+ ACME challenges later) | — |
| `:443`  | hostname-routed vhosts for apps (`*.13.140.173.164.sslip.io`) | server TLS (self-signed for now) |
| `:8889` | **FL coordinator** (URL-stable) | server TLS **+ client-cert mTLS** |

```
                          ┌──────────── HOST nginx (systemd) ────────────┐
   browser ──:443──▶      │ conf.d/00-default.conf  (catch-all, 444)      │
   org cli ──:8889─mTLS▶  │ conf.d/coordinator.conf (verify client cert)  │
   future  ──:443──▶      │ conf.d/<app>.conf       (your vhost)          │
                          └────┬──────────────┬──────────────┬───────────┘
                  proxy_pass   │              │              │   (all to 127.0.0.1:<port>)
                    ┌──────────▼─────┐  ┌──────▼──────┐  ┌────▼─────────┐
                    │ coordinator    │  │ future app  │  │ future app 2 │   (docker,
                    │ 127.0.0.1:8890 │  │ 127.0.0.1:..│  │ 127.0.0.1:.. │    localhost-only)
                    └────────────────┘  └─────────────┘  └──────────────┘
```

## Why host nginx (not a container)
The box hosts multiple things; a host nginx is the simplest single ingress and
avoids cross-compose-project docker networking. Each app stays in its own docker
project, published only on `127.0.0.1:<port>`; nginx fronts them. It also makes
`FL_REQUIRE_MTLS=1` real: plain uvicorn never surfaced the client cert, but nginx
terminates the mTLS handshake, verifies the cert against the **federation CA**,
and forwards it as `X-SSL-Client-Cert`. The coordinator (`FL_TRUSTED_PROXY=1`)
**re-verifies** it (CA + CRL + org-active) and resolves the org. The org URL
stays `…sslip.io:8889`, so enrolled orgs need no reconfiguration.

## Files (this dir → deployed to the server)
- `conf.d/coordinator.conf` → `/etc/nginx/conf.d/` — the `:8889` mTLS vhost → `127.0.0.1:8890`.
- `conf.d/00-default.conf` → `/etc/nginx/conf.d/` — `:80` redirect + `:443` self-signed catch-all.
- `conf.d/example-app.conf.example` — copy-me template for new apps.
- `install.sh` — installs nginx, copies the coordinator cert/key + CA out of the
  docker volume into `/etc/nginx/certs/fl/`, generates the `:443` default cert,
  drops the vhosts, validates + reloads.
- `../docker-compose.mtls.yml` — coordinator overlay: localhost-only publish
  (`127.0.0.1:8890`), plain HTTP, `FL_TRUSTED_PROXY=1`.

## Security model
- **mTLS is real here.** Org `/fl/*` round endpoints require a client cert that
  chains to the federation CA; nginx marks others `!SUCCESS` and the coordinator
  enforces `FL_REQUIRE_MTLS=1`.
- **`ssl_verify_client optional`** (not `on`): enroll-with-token + the operator
  dashboard work *without* a client cert (those paths don't use org-cert identity).
- **Backends are localhost-only.** `X-SSL-Client-Cert` carries a *public* cert
  PEM; the proof of private-key possession is nginx's handshake. The coordinator
  binds `127.0.0.1:8890`, so external clients cannot reach it to spoof the header.
  Do **not** republish the coordinator publicly while `FL_TRUSTED_PROXY=1`.
- **Defense in depth:** the coordinator independently re-verifies the cert
  (CA signature + CRL + org status) even though nginx already terminated TLS.

## Deploy (on the VPS, as root)
```bash
cd /opt/apt-fl-coordinator
git pull                                  # gets the FL_TRUSTED_PROXY middleware + this dir

# 1. rebuild the coordinator image (new middleware) + run it behind the proxy
#    (drops its own TLS; publishes ONLY 127.0.0.1:8890)
docker compose build
docker compose -f docker-compose.yml -f docker-compose.mtls.yml up -d
docker compose -f docker-compose.yml -f docker-compose.mtls.yml ps    # confirm 127.0.0.1:8890

# 2. install + configure host nginx (copies certs out of the docker volume)
cd edge-proxy && sudo bash install.sh
```
If your Docker Compose is < 2.24 (no `!override`), instead edit the base
`docker-compose.yml` coordinator `ports:` to `["127.0.0.1:8890:8889"]`, drop the
`--ssl-*` flags from `command:`, add `FL_TRUSTED_PROXY=1`, and `up -d`.

## Verify
```bash
# operator dashboard / enroll work WITHOUT a client cert:
curl -sk https://13.140.173.164.sslip.io:8889/ -o /dev/null -w '%{http_code}\n'

# org round endpoint needs a valid client cert (real mTLS through nginx):
curl -sk --cert client_cert.pem --key org_ed25519_key.pem \
     https://13.140.173.164.sslip.io:8889/fl/rounds/active        # 200 with a valid cert
#   …without --cert → 401 (FL_REQUIRE_MTLS rejects the certless org path)

# coordinator is NOT publicly reachable except via nginx:
curl -s --max-time 5 http://13.140.173.164:8890/ ; echo "(should refuse/timeout)"
```

## Rollback
```bash
cd /opt/apt-fl-coordinator
docker compose -f docker-compose.yml up -d        # coordinator back to direct TLS on 0.0.0.0:8889
sudo systemctl stop nginx                         # (optional) stop the host proxy
```

## Add a new app
1. Run the app in docker published on `127.0.0.1:<port>` (localhost-only).
2. `cp conf.d/example-app.conf.example /etc/nginx/conf.d/<app>.conf`, set
   `server_name <app>.13.140.173.164.sslip.io` (already resolves) + `proxy_pass
   http://127.0.0.1:<port>`.
3. `sudo nginx -t && sudo systemctl reload nginx`.

## Cert rotation / Let's Encrypt
- The host certs in `/etc/nginx/certs/fl/` are COPIES from the coordinator's
  docker volume. After a CA/coordinator-cert rotation, re-run `install.sh` to
  refresh them, then `systemctl reload nginx`.
- sslip.io names are Let's Encrypt-eligible. To drop browser warnings on the
  `:443` apps later: add certbot (webroot `/.well-known/acme-challenge` is already
  stubbed in `00-default.conf`), then point each vhost's `ssl_certificate*` at the
  issued cert. The coordinator's `:8889` keeps its own sslip.io server cert.
```
