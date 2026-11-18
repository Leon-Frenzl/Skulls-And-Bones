#!/usr/bin/env bash
# Skulls & Bones — One-Command Linux Client Installer
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Leon-Frenzl/Skulls-And-Bones/main/scripts/install.sh | bash
set -euo pipefail

VERSION="${SB_VERSION:-v0.2.3}"
REPO="${SB_REPO:-Leon-Frenzl/Skulls-And-Bones}"

if [[ $EUID -eq 0 ]]; then
  INSTALL_DIR="/usr/local/bin"
else
  INSTALL_DIR="${HOME}/.local/bin"
fi

mkdir -p "$INSTALL_DIR"
TAR_URL="https://github.com/${REPO}/releases/download/${VERSION}/sb-${VERSION}-linux-x86_64.tar.gz"
TMP_TAR="/tmp/sb-${VERSION}-linux-x86_64.tar.gz"

echo "==> Lade ${TAR_URL} ..."
curl -fsSL "$TAR_URL" -o "$TMP_TAR"
tar -xzf "$TMP_TAR" -C "$INSTALL_DIR"
rm -f "$TMP_TAR"
chmod 0755 "${INSTALL_DIR}/sb" "${INSTALL_DIR}/sb-node"

echo ""
echo "✓ Skulls & Bones CLI installiert: ${INSTALL_DIR}"
"${INSTALL_DIR}/sb" --version
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
  echo "  Hinweis: Füge ${INSTALL_DIR} zu deinem PATH hinzu: export PATH=\"${INSTALL_DIR}:\$PATH\""
fi
