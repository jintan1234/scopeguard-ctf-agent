#!/usr/bin/env python3
"""Run recovered integer inputs against the original challenge binary."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: run_solution.py <binary> <solution.json>")
        return 2

    binary = pathlib.Path(sys.argv[1])
    values = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
    if not isinstance(values, list) or not all(isinstance(v, int) for v in values):
        raise SystemExit("solution.json must contain an integer list")

    stdin = "\n".join(map(str, values)) + "\n"
    process = subprocess.run(
        [str(binary)],
        input=stdin,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )

    print(f"decoded_ascii={''.join(chr(v) for v in values)}")
    print(f"exit_code={process.returncode}")
    print(f"stdout={process.stdout!r}")
    print(f"stderr={process.stderr!r}")
    return 0 if process.returncode == 0 and "got it!" in process.stdout else 1


if __name__ == "__main__":
    raise SystemExit(main())
