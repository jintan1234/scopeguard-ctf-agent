set -eu

for tool in r2 rabin2 apktool java javap aapt; do
  command -v "$tool" | sed "s/^/found: /"
done

r2 -v
apktool --version
java -version 2>&1 | head -n 3

if command -v ghidra-analyzeHeadless >/dev/null 2>&1; then
  echo "ghidra=present"
else
  echo "ghidra=missing-network-blocked"
fi

if command -v jadx >/dev/null 2>&1; then
  echo "jadx=present"
else
  echo "jadx=missing-network-blocked"
fi
