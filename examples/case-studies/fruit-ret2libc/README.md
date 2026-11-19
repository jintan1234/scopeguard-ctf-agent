# Case study: two-stage ret2libc

This case study preserves the exploitation chain and verified result from an
authorized internal CTF challenge.

```text
Target: 183.238.63.200:45711/TCP
Flag: 7a05d1dfc4bf420abba8956931189635
Assurance: reproducible_evidence
```

## Vulnerability

- x86-64 ELF;
- non-PIE;
- stack buffer overflow through a coupon input;
- 24-byte offset to the saved return address;
- no canary;
- Partial RELRO.

## Chain

1. Select the menu path that reaches the Coupon handler.
2. Overflow 24 bytes and call:

```text
pop rdi; ret
puts@got
puts@plt
main
```

3. Consume the exact output boundaries after `[+] OK~`.
4. Read the leaked six-byte `puts` pointer.
5. Resolve the remote libc from the leak.
6. Build a second chain:

```text
ret
pop rdi; ret
"/bin/sh"
system
```

7. Run `cat /flag`.

## Why the first attempts failed

### Failure 1: wrong line parsed as the leak

The program printed:

```text
[+] OK~

<six-byte puts pointer>
```

The first attempt read the blank line and interpreted it as `0x0`.

Correction:

```python
io.recvuntil(b"[+] OK~\n\n")
leak = u64(io.recvline(drop=True).ljust(8, b"\x00"))
```

### Failure 2: incorrect local payload assertion

The stage-two payload contains four addresses:

```text
24 bytes padding + 4 * 8 bytes ROP = 56 bytes
```

An incorrect assertion expected five addresses and stopped the script before
the payload was transmitted.

## Sanitized exploit

See [`exp.py`](exp.py).

The script defaults to the historical target. Override these variables for a
different authorized copy:

```text
CTF_TARGET_HOST
CTF_TARGET_PORT
CTF_FRUIT_BINARY
```

The historical target may be offline or reassigned. Running the script does
not grant authorization to contact it.

## Evidence expected from a successful run

- first-stage leak;
- selected libc build;
- page-aligned libc base;
- final shell transcript;
- exact Flag `7a05d1dfc4bf420abba8956931189635`;
- SHA-256 for the transcript.
