set -eu
sqlmap --version
gobuster version
printf 'network='
python - <<'PY'
import socket
sock = socket.socket()
sock.settimeout(2)
print("reachable" if sock.connect_ex(("1.1.1.1", 80)) == 0 else "blocked")
PY
