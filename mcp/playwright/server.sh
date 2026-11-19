#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
export CTF_AGENT_ROOT="${CTF_AGENT_ROOT:-$ROOT}"
export CTF_PLAYWRIGHT_OUTPUT_DIR="${CTF_PLAYWRIGHT_OUTPUT_DIR:-$ROOT/challenges/current/browser-output}"
export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD="${PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD:-1}"

mkdir -p "$CTF_PLAYWRIGHT_OUTPUT_DIR"

exec node "$ROOT/mcp/playwright/launcher.js" \
  --headless \
  --browser chromium \
  --no-sandbox \
  --isolated \
  --timeout-action 10000 \
  --timeout-navigation 30000 \
  --console-level warning \
  --output-dir "$CTF_PLAYWRIGHT_OUTPUT_DIR" \
  --blocked-origins "http://169.254.169.254;http://127.0.0.1:2375;http://localhost:2375"
