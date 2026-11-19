#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
export PYTHONPATH="$ROOT/tools${PYTHONPATH:+:$PYTHONPATH}"
export CTF_AGENT_ROOT="${CTF_AGENT_ROOT:-$ROOT}"
export CTF_DOCKER_BROKER_URL="${CTF_DOCKER_BROKER_URL:-http://127.0.0.1:8765}"
export CTF_DOCKER_BROKER_TOKEN_FILE="${CTF_DOCKER_BROKER_TOKEN_FILE:-$ROOT/config/docker-broker-token}"

if [ -n "${CTF_PYTHON:-}" ]; then
  PYTHON="$CTF_PYTHON"
elif [ -x "$ROOT/.venv/bin/python" ]; then
  PYTHON="$ROOT/.venv/bin/python"
else
  PYTHON=python3
fi

exec "$PYTHON" -m ctf_core.mcp_server
