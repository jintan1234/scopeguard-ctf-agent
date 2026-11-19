#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
asset_root="${CTF_THIRD_PARTY:-$PROJECT_ROOT/third_party}"
install_root=/opt/ctf-tools

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  gdb \
  openjdk-21-jdk-headless \
  ca-certificates \
  python3-venv

mkdir -p "$install_root/bin"

zcat "$asset_root/chisel_1.12.0_linux_amd64.gz" > "$install_root/bin/chisel"
chmod 0755 "$install_root/bin/chisel"

tar -xzf "$asset_root/ligolo-ng_agent_0.9.2_linux_amd64.tar.gz" -C "$install_root/bin"
tar -xzf "$asset_root/ligolo-ng_proxy_0.9.2_linux_amd64.tar.gz" -C "$install_root/bin"
chmod 0755 "$install_root/bin/agent" "$install_root/bin/proxy"

ln -sfn "$install_root/bin/chisel" /usr/local/bin/chisel
ln -sfn "$install_root/bin/agent" /usr/local/bin/ligolo-agent
ln -sfn "$install_root/bin/proxy" /usr/local/bin/ligolo-proxy

echo "WSL_RUNTIME_INSTALLED"
gdb --version | head -n 1
java -version 2>&1 | head -n 1
chisel --version
ligolo-agent -h 2>&1 | head -n 2
ligolo-proxy -h 2>&1 | head -n 2
