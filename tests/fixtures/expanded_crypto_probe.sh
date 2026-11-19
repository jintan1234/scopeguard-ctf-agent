set -eu

command -v sage
sage --version
sage -python - <<'PY'
import sympy

print("sympy", sympy.__version__)
PY
