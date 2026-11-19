set -eu

for tool in ffuf gobuster sqlmap nikto whatweb smbclient rpcclient mitmdump mitmweb wpscan; do
  command -v "$tool" | sed "s/^/found: /"
done

ffuf -V
gobuster version
sqlmap --version
nikto -Version 2>&1 | head -n 2
whatweb --version
mitmdump --version | head -n 2
python - <<'PY'
import importlib.metadata
import impacket

print("impacket", importlib.metadata.version("impacket"))
print("mitmproxy", importlib.metadata.version("mitmproxy"))
PY

printf 'network='
python - <<'PY'
import socket

sock = socket.socket()
sock.settimeout(2)
print("reachable" if sock.connect_ex(("1.1.1.1", 80)) == 0 else "blocked")
PY
