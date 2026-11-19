#!/usr/bin/env python3
"""Recover the easyIDA Flag by emulating the original function."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_RSP


FLAG_FUNCTION_RVA = 0x14A0
FLAG_STOP_RVA = 0x14FF
FLAG_BUFFER_RVA = 0xD040
STACK_BASE = 0x700000000000
STACK_SIZE = 0x10000


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: solve.py path/to/flag.exe")
        return 2

    binary = Path(sys.argv[1]).resolve()
    data = binary.read_bytes()
    pe = pefile.PE(data=data, fast_load=False)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    image_size = pe.OPTIONAL_HEADER.SizeOfImage

    emulator = Uc(UC_ARCH_X86, UC_MODE_64)
    emulator.mem_map(image_base, (image_size + 0xFFF) & ~0xFFF)
    emulator.mem_write(image_base, pe.get_memory_mapped_image())
    emulator.mem_map(STACK_BASE, STACK_SIZE)
    emulator.reg_write(
        UC_X86_REG_RSP,
        STACK_BASE + STACK_SIZE - 0x100,
    )
    emulator.emu_start(
        image_base + FLAG_FUNCTION_RVA,
        image_base + FLAG_STOP_RVA,
        count=100_000,
    )

    buffer_address = image_base + FLAG_BUFFER_RVA
    raw = bytes(emulator.mem_read(buffer_address, 0x40)).split(b"\0", 1)[0]
    flag = raw.decode("ascii")

    print(f"binary_sha256={hashlib.sha256(data).hexdigest()}")
    print("credentials=admin:passwordF")
    print(f"flag={flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
