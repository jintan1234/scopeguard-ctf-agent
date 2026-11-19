#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CONFIG="${CODEX_HOME:-$HOME/.codex}/config.toml"
SECTION="[projects.'$(printf '%s' "$ROOT" | tr '[:upper:]' '[:lower:]')']"

if [ ! -f "$CONFIG" ]; then
  echo "Codex config not found: $CONFIG" >&2
  exit 1
fi

if grep -F -q "$SECTION" "$CONFIG"; then
  echo "Project trust entry already exists."
  exit 0
fi

STAMP=$(date +%Y%m%d-%H%M%S)
cp "$CONFIG" "$CONFIG.backup-$STAMP"
printf '\n%s\ntrust_level = "trusted"\n' "$SECTION" >> "$CONFIG"
echo "Backup: $CONFIG.backup-$STAMP"
echo "Added project trust entry: $SECTION"
