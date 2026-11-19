---
name: ctf-pwn
description: Use for authorized binary exploitation challenges including stack/heap corruption, format strings, ROP, ret2libc, integer bugs, sandbox escapes and remote process interaction.
---

# Pwn

## Initial analysis

1. Inspect the binary and libc.
2. Run checksec: architecture, PIE, NX, canary, RELRO.
3. List imports, symbols, strings and dangerous call sites.
4. Run locally in the Pwn sandbox.
5. Fuzz only with bounded, targeted inputs.
6. Determine exact crash offset and control.

## Exploit loop

1. Reproduce locally.
2. Build the smallest pwntools script.
3. Verify offset and primitive.
4. Add leak, ROP or heap interaction.
5. Reproduce multiple times.
6. Connect only to the authorized remote host/port.
7. Save transcript and flag artifact.

## Common paths

- Stack overflow: cyclic offset, RIP control, ret2win/ret2libc.
- Format string: positional leaks, arbitrary write.
- Integer bug: signedness, truncation, overflow in allocation/indexing.
- Heap: identify allocator/version, chunk layout and primitive.
- ROP: gadget quality, stack alignment, libc offsets.
- Sandbox: identify seccomp/open/read/write restrictions before designing chain.

## Libc

Use build ID or symbol fingerprints. Do not guess a libc from three offsets alone.

## Safety

- Do not attack hosts beyond the scope.
- Do not use denial-of-service payloads on shared targets.
- Do not mount host credentials or Docker socket into the exploit container.
- Keep CPU, memory, pids and timeout limits.

## Evidence

Store the exploit, local debug transcript, remote transcript and a proof artifact containing the flag. If no external validator exists, mark it `reproducible_evidence`.
