#!/bin/sh
set -eu

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
pwndbg_venv=/opt/ctf-tools/venvs/pwndbg
pwndbg_src="${CTF_PWNDBG_SOURCE:-$PROJECT_ROOT/tool-runtime/pwn/pwndbg-9760ac8f1346d142857cffc933995cd6fca34dff}"
pt_src="${CTF_PT_SOURCE:-$PROJECT_ROOT/tool-runtime/pwn/gdb-pt-dump-50227bda0b6332e94027f811a15879588de6d5cb}"

export PWNDBG_VENV_PATH="$pwndbg_venv"
export PWNDBG_NO_AUTOUPDATE=1
export PYTHONPATH="$pt_src${PYTHONPATH:+:$PYTHONPATH}"

exec gdb -q \
  -ex "source $pwndbg_src/gdbinit.py" \
  "$@"
