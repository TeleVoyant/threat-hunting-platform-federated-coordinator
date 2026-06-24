#!/usr/bin/env bash
# Install + configure HOST nginx as the server's reverse proxy on the Contabo VPS.
# Run as root from this directory:  sudo bash install.sh
# Idempotent-ish: safe to re-run (re-copies certs + vhosts, reloads).
#
# PREREQUISITE: the coordinator must already be running BEHIND the proxy, i.e.
# published on 127.0.0.1:8890 (plain HTTP) via the overlay:
#     cd /opt/apt-fl-coordinator
#     docker compose -f docker-compose.yml -f docker-compose.mtls.yml up -d
set -euo pipefail
cd "$(dirname "$0")"

CERTS=/etc/nginx/certs
VOL_NAME="${COORD_VOLUME:-apt-fl-coordinator_fl-coordinator-data}"

echo "==> installing nginx + openssl"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y nginx openssl

echo "==> locating coordinator CA inside docker volume '$VOL_NAME'"
VOL_DIR="$(docker volume inspect "$VOL_NAME" -f '{{ .Mountpoint }}')"
CA_DIR="$VOL_DIR/ca"
test -f "$CA_DIR/coordinator_cert.pem" || { echo "ERROR: $CA_DIR/coordinator_cert.pem not found"; exit 1; }

echo "==> installing certs to $CERTS"
mkdir -p "$CERTS/fl" "$CERTS/default"
cp "$CA_DIR/coordinator_cert.pem" "$CERTS/fl/"
cp "$CA_DIR/coordinator_key.pem"  "$CERTS/fl/"
cp "$CA_DIR/ca_cert.pem"          "$CERTS/fl/"
chmod 600 "$CERTS/fl/coordinator_key.pem"
if [ ! -f "$CERTS/default/default_cert.pem" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$CERTS/default/default_key.pem" -out "$CERTS/default/default_cert.pem" \
    -days 3650 -subj "/CN=default.invalid"
  chmod 600 "$CERTS/default/default_key.pem"
fi

echo "==> installing vhosts (dropping the distro default site)"
rm -f /etc/nginx/sites-enabled/default
cp conf.d/00-default.conf conf.d/coordinator.conf /etc/nginx/conf.d/

echo "==> validating + reloading"
nginx -t
systemctl enable nginx
systemctl reload nginx || systemctl restart nginx
echo "==> done: host nginx fronts :80 :443 :8889  (coordinator via 127.0.0.1:8890)"
echo "    NOTE: re-run after a CA rotation to refresh $CERTS/fl/*.pem"
