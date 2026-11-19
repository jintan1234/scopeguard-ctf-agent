#!/usr/bin/env python3
"""Recover a ten-block XOR plus zlib protected DEX payload."""

from __future__ import annotations

import hashlib
import pathlib
import struct
import sys
import zlib


PAYLOAD_FILE_OFFSET = 0x6004
LENGTH_FILE_OFFSET = 0x42A18


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: recover_easy_dex.py <libnative.so> <classes.dex>")
        return 2

    source = pathlib.Path(sys.argv[1])
    output = pathlib.Path(sys.argv[2])
    data = source.read_bytes()

    payload_length = struct.unpack_from("<I", data, LENGTH_FILE_OFFSET)[0]
    encrypted = bytearray(
        data[PAYLOAD_FILE_OFFSET : PAYLOAD_FILE_OFFSET + payload_length]
    )
    if len(encrypted) != payload_length:
        raise ValueError("embedded payload is truncated")

    chunk_size = payload_length // 10
    for index in range(9):
        key = 9 + index * 10
        start = index * chunk_size
        end = start + chunk_size
        for offset in range(start, end):
            encrypted[offset] ^= key
    for offset in range(9 * chunk_size, payload_length):
        encrypted[offset] ^= 0x59

    compressed = bytes(encrypted)
    decompressed = zlib.decompress(compressed)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(decompressed)

    print(f"payload_length={payload_length}")
    print(f"chunk_size={chunk_size}")
    print(f"compressed_sha256={hashlib.sha256(compressed).hexdigest()}")
    print(f"decompressed_size={len(decompressed)}")
    print(f"decompressed_sha256={hashlib.sha256(decompressed).hexdigest()}")
    print(f"dex_magic={decompressed[:8]!r}")
    print(f"output={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
