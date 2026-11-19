from __future__ import annotations

import argparse
import base64
import py_compile
import zipfile
from pathlib import Path


MISC_FLAG = "FLAG{MISC_ZIP_LOCAL_TEST}"
CRYPTO_FLAG = "FLAG{CRYPTO_BASE64_XOR_LOCAL_TEST}"
REVERSE_FLAG = "FLAG{PY_BYTECODE_LOCAL_TEST}"


def make_fixtures(output: Path) -> list[Path]:
    output.mkdir(parents=True, exist_ok=True)

    archive = output / "misc-archive.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("notes/readme.txt", "This archive contains a nested recovery task.\n")
        handle.writestr("notes/secret.txt", MISC_FLAG + "\n")

    xored = bytes(value ^ 0x6D for value in CRYPTO_FLAG.encode("ascii"))
    crypto = output / "crypto-chain.txt"
    crypto.write_text(base64.b64encode(xored).decode("ascii"), encoding="ascii")

    source = output / "reverse-source.py"
    source.write_text(
        "def unlock():\n"
        f"    return {REVERSE_FLAG!r}\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    print(unlock())\n",
        encoding="utf-8",
    )
    pyc = output / "reverse-challenge.pyc"
    py_compile.compile(str(source), cfile=str(pyc), doraise=True)

    manifest = output / "manifest.txt"
    manifest.write_text(
        f"misc={MISC_FLAG}\ncrypto={CRYPTO_FLAG}\nreverse={REVERSE_FLAG}\n",
        encoding="utf-8",
    )
    return [archive, crypto, pyc, manifest]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "fixtures" / "generated",
    )
    args = parser.parse_args()
    for path in make_fixtures(args.output.resolve()):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
