set -eu
export TERM=xterm

echo "== versions =="
zsteg --version || true
stegseek --version || true

echo "== stegseek round trip =="
python - <<'PY'
from PIL import Image
Image.new("RGB", (128, 128), (96, 128, 160)).save("/challenge/work/cover.bmp")
PY
printf 'flag{stegseek_roundtrip}\n' > /challenge/work/secret.txt
printf 'alpha\nhunter2\nomega\n' > /challenge/work/words.txt
steghide embed -cf /challenge/work/cover.bmp -ef /challenge/work/secret.txt -p hunter2 -f
stegseek /challenge/work/cover.bmp /challenge/work/words.txt -xf /challenge/work/extracted.txt > /challenge/artifacts/stegseek.log 2>&1
cat /challenge/work/extracted.txt
grep -F 'flag{stegseek_roundtrip}' /challenge/work/extracted.txt

echo "== zsteg round trip =="
python - <<'PY'
from PIL import Image
message = b"flag{zsteg_roundtrip}"
bits = ''.join(f"{byte:08b}" for byte in message)
image = Image.new("RGBA", (len(bits), 1), (0, 0, 0, 255))
pixels = image.load()
for x, bit in enumerate(bits):
    pixels[x, 0] = (int(bit), 0, 0, 255)
image.save("/challenge/work/lsb.png")
PY
zsteg -E 'b1,r,lsb,xy' /challenge/work/lsb.png > /challenge/artifacts/zsteg.bin
grep -a -F 'flag{zsteg_roundtrip}' /challenge/artifacts/zsteg.bin

echo "stego-roundtrip-ok"
