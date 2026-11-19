---
name: ctf-reverse
description: Use for Windows PE, ELF, APK, Java, .NET, Python bytecode, WASM, packed binaries, custom VMs and static or dynamic reverse-engineering challenges.
---

# Reverse Engineering

## Triage

Use `ctf_file_inspect` first, then identify:

- architecture and bitness;
- format and runtime;
- imports/sections/symbols;
- packing, entropy and overlays;
- architecture strings and suspicious constants;
- expected input/output behavior.

## Static-first workflow

1. Strings and cross-references.
2. Symbol/import review.
3. Entry point and main flow.
4. Input validation/compare loops.
5. Transform or crypto routines.
6. Reimplement the inverse in a script.
7. Verify on multiple inputs and recover the exact flag.

Prefer headless tools:

- radare2/r2pipe for quick structure and scripts.
- Ghidra analyzeHeadless with postScript for decompilation/xrefs.
- objdump/readelf/PE tools for format details.
- JADX/apktool for Android.
- javap/CFR for Java.
- Python bytecode decompilers for `.pyc`.
- ILSpy/dnSpyEx for .NET.

## Dynamic analysis

Use only in an isolated container/VM. Record environment, input, breakpoints, register/memory state and output.

For anti-debug:

- identify checks before patching;
- try emulation or snapshot-based execution;
- do not disable host security controls.

## Patching

- Copy the binary before mutation.
- Record byte offsets and hashes before/after.
- Keep a patch script or diff.
- Verify patched behavior and whether the flag changes.

## Flag generation

Many reverse flags are produced from input transformations. Recover the inverse function and rerun the original binary when possible.

## GUI

Use Ghidra/IDA GUI only for functions that cannot be represented efficiently through headless output, especially graph navigation and interactive debugging.
