#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SOURCE="$ROOT/config/codex-mcp.project.linux.toml.example"
TARGET="$ROOT/.codex/config.toml"

if [ ! -f "$SOURCE" ]; then
  echo "MCP configuration template is missing: $SOURCE" >&2
  exit 1
fi

mkdir -p "$ROOT/.codex"
if [ -f "$TARGET" ]; then
  STAMP=$(date +%Y%m%d-%H%M%S)
  cp "$TARGET" "$TARGET.backup-$STAMP"
  echo "Backed up project config to $TARGET.backup-$STAMP"
fi

sed "s#<PROJECT_ROOT>#$ROOT#g" "$SOURCE" > "$TARGET"
echo "Installed project-scoped MCP configuration: $TARGET"
echo "Start a new Codex thread in this project so the MCP servers are loaded."
