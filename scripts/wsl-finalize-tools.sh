#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
asset_root="${CTF_TOOL_RUNTIME:-$PROJECT_ROOT/tool-runtime}"
install_root=/opt/ctf-tools

mkdir -p "$install_root/bin"

install -m 0755 "$asset_root/web/nuclei" "$install_root/bin/nuclei"
install -m 0755 "$asset_root/web/httpx" "$install_root/bin/httpx"
install -m 0755 "$asset_root/web/katana" "$install_root/bin/katana"
install -m 0755 "$asset_root/web/feroxbuster" "$install_root/bin/feroxbuster"

ln -sfn "$install_root/bin/nuclei" /usr/local/bin/nuclei
ln -sfn "$install_root/bin/httpx" /usr/local/bin/httpx
ln -sfn "$install_root/bin/katana" /usr/local/bin/katana
ln -sfn "$install_root/bin/feroxbuster" /usr/local/bin/feroxbuster
ln -sfn "$install_root/bin/chisel" /usr/local/bin/chisel
ln -sfn "$install_root/bin/agent" /usr/local/bin/ligolo-agent
ln -sfn "$install_root/bin/proxy" /usr/local/bin/ligolo-proxy

cat > /usr/local/bin/jadx <<EOF
#!/bin/sh
export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64
export PATH="\$JAVA_HOME/bin:\$PATH"
exec "$asset_root/jadx/bin/jadx" "\$@"
EOF

cat > /usr/local/bin/ghidra-analyzeHeadless <<EOF
#!/bin/sh
export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64
export PATH="\$JAVA_HOME/bin:\$PATH"
exec bash "$asset_root/ghidra/ghidra_12.2_PUBLIC/support/analyzeHeadless" "\$@"
EOF

cat > /usr/local/bin/gdb-gef <<EOF
#!/bin/sh
exec gdb -q \
  -ex "source $asset_root/pwn/gef-809864d00442f9993298e33fd9cd282d687d2f45/gef.py" \
  "\$@"
EOF

chmod 0755 \
  /usr/local/bin/jadx \
  /usr/local/bin/ghidra-analyzeHeadless \
  /usr/local/bin/gdb-gef

echo "WSL_TOOLS_FINALIZED"
for tool in nuclei httpx katana feroxbuster chisel ligolo-agent ligolo-proxy jadx ghidra-analyzeHeadless gdb-gef; do
  command -v "$tool"
done
