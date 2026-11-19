#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

CONFIGURE_CODEX=0
TRUST_PROJECT=0
BUILD_ANALYSIS=0
SKIP_BROWSER=0

for arg in "$@"; do
  case "$arg" in
    --configure-codex) CONFIGURE_CODEX=1 ;;
    --trust-project) TRUST_PROJECT=1 ;;
    --build-analysis) BUILD_ANALYSIS=1 ;;
    --skip-browser) SKIP_BROWSER=1 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

echo "== ScopeGuard bootstrap =="
echo "Root: $ROOT"

if [ ! -x "$ROOT/.venv/bin/python" ]; then
  python3 -m venv "$ROOT/.venv"
fi

PYTHON="$ROOT/.venv/bin/python"
"$PYTHON" -m pip install --upgrade pip setuptools wheel
"$PYTHON" -m pip install -r "$ROOT/requirements-core.txt"
"$PYTHON" -m pip install -e "$ROOT"

if [ "$SKIP_BROWSER" -eq 0 ]; then
  (
    cd "$ROOT/mcp/playwright"
    npm ci
    export PLAYWRIGHT_BROWSERS_PATH="$ROOT/mcp/playwright/browsers"
    npx playwright install chromium
  )
fi

mkdir -p "$ROOT/challenges/current" "$ROOT/logs"

if [ "$CONFIGURE_CODEX" -eq 1 ]; then
  sh "$ROOT/scripts/enable-codex-mcp.sh"
fi

if [ "$TRUST_PROJECT" -eq 1 ]; then
  sh "$ROOT/scripts/trust-project.sh"
fi

export CTF_PYTHON="$PYTHON"
export PYTHONPATH="$ROOT/tools"
export PYTHONDONTWRITEBYTECODE=1

"$PYTHON" -m unittest discover -s "$ROOT/tests" -v
"$PYTHON" "$ROOT/examples/quickdemo/demo.py"

if [ "$BUILD_ANALYSIS" -eq 1 ]; then
  docker build \
    -t ctf-agent/analysis:0.2 \
    -f "$ROOT/docker/analysis/Dockerfile" \
    "$ROOT/docker/analysis"
fi

echo
echo "Bootstrap complete."
if [ "$CONFIGURE_CODEX" -eq 0 ]; then
  echo "Configure Codex MCP with:"
  echo "  sh scripts/enable-codex-mcp.sh"
fi
echo "Start the Docker broker in a second terminal:"
echo "  .venv/bin/python mcp/docker-broker/broker.py --root \"$ROOT\" --host 127.0.0.1 --port 8765"
echo "Then start Codex from this directory:"
echo "  codex"
