#!/usr/bin/env bash
# Skulls & Bones — One-Command Sovereign Domain Controller Installer (Ubuntu/Debian)
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/<org>/<repo>/main/scripts/install-dc.sh | sudo bash -s -- \
#     --domain skulls-and-bones.sb \
#     --console-host console.skulls-and-bones.org \
#     --enroll-host enroll.skulls-and-bones.org \
#     --admin leon.admin
set -euo pipefail

DOMAIN="skulls-and-bones.sb"
CONSOLE_HOST=""
ENROLL_HOST=""
ADMIN_USER="sb.admin"
ADMIN_PASSWORD=""
RELEASE_TARBALL_URL=""
SRC_DIR="/opt/skulls-and-bones"
BIN_DIR="/usr/local/bin"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --console-host) CONSOLE_HOST="$2"; shift 2 ;;
    --enroll-host) ENROLL_HOST="$2"; shift 2 ;;
    --admin) ADMIN_USER="$2"; shift 2 ;;
    --password) ADMIN_PASSWORD="$2"; shift 2 ;;
    --tarball-url) RELEASE_TARBALL_URL="$2"; shift 2 ;;
    --src-dir) SRC_DIR="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,10p' "$0"
      exit 0
      ;;
    *)
      echo "Unbekanntes Argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Fehler: Bitte als root oder via sudo ausführen." >&2
  exit 1
fi

if [[ -z "$CONSOLE_HOST" ]]; then
  CONSOLE_HOST="console.${DOMAIN}"
fi
if [[ -z "$ENROLL_HOST" ]]; then
  ENROLL_HOST="enroll.${DOMAIN}"
fi

echo "==> [1/6] Systempakete, UFW & Fail2ban einrichten..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates ufw fail2ban caddy tar gzip

ufw allow 22/tcp >/dev/null
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw --force enable >/dev/null
systemctl enable --now fail2ban >/dev/null

echo "==> [2/6] sb & sb-node Binaries bereitstellen..."
if [[ -n "$RELEASE_TARBALL_URL" ]]; then
  TMP_TAR="/tmp/sb-release.tar.gz"
  curl -fsSL "$RELEASE_TARBALL_URL" -o "$TMP_TAR"
  tar -xzf "$TMP_TAR" -C "$BIN_DIR"
  rm -f "$TMP_TAR"
  chmod 0755 "$BIN_DIR/sb" "$BIN_DIR/sb-node"
elif [[ -f "$SRC_DIR/Cargo.toml" ]]; then
  if ! command -v cargo >/dev/null 2>&1; then
    echo "Fehler: cargo nicht gefunden und kein --tarball-url angegeben." >&2
    exit 1
  fi
  (cd "$SRC_DIR" && cargo build --release -p sb-node -p sb-cli)
  install -m 0755 "$SRC_DIR/target/release/sb-node" "$BIN_DIR/sb-node"
  install -m 0755 "$SRC_DIR/target/release/sb" "$BIN_DIR/sb"
else
  echo "Fehler: Weder --tarball-url noch $SRC_DIR/Cargo.toml vorhanden." >&2
  exit 1
fi

echo "==> [3/6] Caddy TLS Reverse Proxy konfigurieren ($CONSOLE_HOST, $ENROLL_HOST)..."
cat >/etc/caddy/Caddyfile <<EOF
${CONSOLE_HOST} {
    reverse_proxy 127.0.0.1:8090
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
    }
}

${ENROLL_HOST} {
    handle /enroll* {
        reverse_proxy 127.0.0.1:8090
    }
    handle /v1/enrollments* {
        reverse_proxy 127.0.0.1:8090
    }
    handle /v1/health {
        reverse_proxy 127.0.0.1:8090
    }
    handle {
        respond "403 Forbidden" 403
    }
}
EOF
systemctl enable --now caddy
systemctl reload caddy

echo "==> [4/6] systemd Service sb-dc.service installieren..."
CONSOLE_DIST_ARG=""
if [[ -d "$SRC_DIR/console/dist" ]]; then
  CONSOLE_DIST_ARG="--console-dir $SRC_DIR/console/dist"
fi

cat >/etc/systemd/system/sb-dc.service <<EOF
[Unit]
Description=Skulls & Bones Sovereign Domain Controller ($DOMAIN)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_DIR/sb-node dc up --domain $DOMAIN --admin $ADMIN_USER --dc-bind 127.0.0.1:8443 --graph-bind 127.0.0.1:8090 $CONSOLE_DIST_ARG
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now sb-dc.service
sleep 2

echo "==> [5/6] Admin-Passwort & Baseline-GPO einrichten..."
if [[ -z "$ADMIN_PASSWORD" ]]; then
  ADMIN_PASSWORD="$(tr -dc 'A-Za-z0-9!@#%^&*' </dev/urandom | head -c 20)"
  GENERATED_PW=1
else
  GENERATED_PW=0
fi

"$BIN_DIR/sb-node" user set-password "$ADMIN_USER" --password "$ADMIN_PASSWORD"
"$BIN_DIR/sb-node" policy init "$DOMAIN" >/dev/null 2>&1 || true
"$BIN_DIR/sb-node" policy put \
  --id baseline-all \
  --domain "$DOMAIN" \
  --name Baseline-SplitDNS-SSH \
  --os all \
  --ssh-hardening \
  --dns-domains "$DOMAIN" \
  --dns-servers 10.42.0.1

echo "==> [6/6] Abschlussprüfung..."
systemctl is-active --quiet sb-dc.service
systemctl is-active --quiet caddy

echo ""
echo "================================================================"
echo "  Skulls & Bones Domain Controller ist einsatzbereit!"
echo "================================================================"
echo "  Domäne:         $DOMAIN"
echo "  Web-Konsole:    https://$CONSOLE_HOST"
echo "  Self-Service:   https://$ENROLL_HOST/enroll"
echo "  Admin-User:     $ADMIN_USER"
if [[ "$GENERATED_PW" -eq 1 ]]; then
  echo "  Admin-Passwort: $ADMIN_PASSWORD  (bitte sicher ablegen!)"
fi
echo ""
echo "  Client-Join auf jedem Rechner:"
echo "    sb join $DOMAIN --dc https://$CONSOLE_HOST --username $ADMIN_USER"
echo "================================================================"
