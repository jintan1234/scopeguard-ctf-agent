#!/usr/bin/env python3
"""Extract a fake-encrypted ZIP using its local raw-DEFLATE payload."""

from __future__ import annotations

import sys
import zlib
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: solve.py path/to/flag.zip")
        return 2

    data = Path(sys.argv[1]).read_bytes()
    if data[:4] != b"PK\x03\x04":
        raise SystemExit("not a ZIP local header")

    name_length = int.from_bytes(data[26:28], "little")
    extra_length = int.from_bytes(data[28:30], "little")
    compressed_size = int.from_bytes(data[18:22], "little")
    start = 30 + name_length + extra_length
    payload = data[start : start + compressed_size]
    plain = zlib.decompress(payload, -15)
    print(plain.decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
