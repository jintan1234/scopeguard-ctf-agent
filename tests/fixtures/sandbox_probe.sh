set -eu
export TERM=xterm
printf 'sandbox-write-ok\n' > /challenge/work/probe.txt
printf 'artifact-write-ok\n' > /challenge/artifacts/probe.txt

echo "== tools =="
for tool in file 7z binwalk foremost exiftool identify pngcheck steghide tshark fls mmls ffmpeg tesseract yara gdb strace ltrace hashcat john nmap xfreerdp Xvfb xvfb-run xdotool; do
  command -v "$tool" | sed "s/^/found: /"
done

echo "== versions =="
tshark --version | head -n 1
exiftool -ver
7z | head -n 2 | tail -n 1
binwalk --help >/dev/null && echo binwalk-cli-ok
foremost -V 2>&1 | head -n 1
yara --version
gdb --version | head -n 1
hashcat --version
john --help 2>&1 | head -n 3
nmap --version | head -n 1
xfreerdp /version 2>&1 | head -n 1

echo "== python =="
python - <<'PY'
import sys
import Crypto
import sympy
import z3
import capstone
import elftools
import pefile
import scapy
import volatility3
import yara
import importlib.metadata
from pwn import context
from pwnlib.version import __version__ as pwntools_version
print(sys.version)
print('Crypto', Crypto.__version__)
print('sympy', sympy.__version__)
print('z3', z3.get_version_string())
print('capstone', capstone.__version__)
print('pwntools', pwntools_version)
print('volatility3', importlib.metadata.version('volatility3'))
print('yara-python', importlib.metadata.version('yara-python'))
PY

echo "== runtime isolation =="
printf 'network="'
python - <<'PY'
import socket
try:
    socket.create_connection(('1.1.1.1', 80), timeout=2)
    print('reachable')
except Exception as exc:
    print(type(exc).__name__)
PY
printf '"\n'

printf 'files="'
find /challenge -maxdepth 2 -type f -printf '%p ' | sort
printf '"\n'
