#!/usr/bin/env bash
set -u

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tool_root="${CTF_TOOL_RUNTIME:-$PROJECT_ROOT/tool-runtime}"

echo "== mounted executable tools =="
"$tool_root/web/nuclei" -version
"$tool_root/web/httpx" -version
"$tool_root/web/katana" -version
"$tool_root/web/feroxbuster" --version
"$tool_root/jadx/bin/jadx" --version

echo "== copy-required tools =="
chisel --version
ligolo-agent -h 2>&1 | head -n 3
ligolo-proxy -h 2>&1 | head -n 3

echo "== ghidra =="
JAVA_BIN=$(readlink -f "$(command -v java)")
export JAVA_HOME=$(dirname "$(dirname "$JAVA_BIN")")
export PATH="$JAVA_HOME/bin:$PATH"
echo "JAVA_HOME=$JAVA_HOME"
bash "$tool_root/ghidra/ghidra_12.2_PUBLIC/support/analyzeHeadless" 2>&1 | head -n 12 || true

echo "== debugger plugins =="
if command -v gdb >/dev/null 2>&1; then
  gdb -q -batch \
    -ex "source $tool_root/pwn/gef-809864d00442f9993298e33fd9cd282d687d2f45/gef.py" \
    -ex "echo GEF_LOADED\\n" \
    -ex quit 2>&1 | tail -n 8
  gdb -q -batch \
    -ex "source $tool_root/pwn/pwndbg-9760ac8f1346d142857cffc933995cd6fca34dff/gdbinit.py" \
    -ex "echo PWNDBG_LOADED\\n" \
    -ex quit 2>&1 | tail -n 12
else
  echo "gdb=missing"
fi

echo "== privilege =="
id -u
if sudo -n true 2>/dev/null; then
  echo sudo=available
else
  echo sudo=requires-password-or-unavailable
fi
