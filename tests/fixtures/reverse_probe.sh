set -eu
java -version 2>&1 | head -n 3
javap -version
printf 'network='
python - <<'PY'
import socket
sock = socket.socket()
sock.settimeout(2)
print("reachable" if sock.connect_ex(("1.1.1.1", 80)) == 0 else "blocked")
PY
