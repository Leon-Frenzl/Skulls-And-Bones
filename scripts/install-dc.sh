#!/usr/bin/env bash
# Deprecated wrapper: delegates Domain Controller setup to the unified `sb server dc-init` CLI.
set -euo pipefail

if ! command -v sb >/dev/null 2>&1; then
  echo "Fehler: 'sb' nicht gefunden. Installiere zuerst die S&B CLI via scripts/install.sh." >&2
  exit 1
fi

echo "Hinweis: scripts/install-dc.sh ist veraltet und delegiert direkt an 'sb server dc-init'." >&2
exec sb server dc-init "$@"
