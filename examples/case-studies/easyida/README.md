# Case study: easyIDA Windows PE reverse engineering

Offline reverse-engineering challenge.

```text
Target: local 64-bit Windows PE
Flag: flag{simple_reverse}
Assurance: reproducible_evidence
```

## Analysis

The validator checks:

```text
username = admin
password = passwordF
```

On success, function RVA `0x14A0` reads an embedded `.rdata` byte string and
subtracts one from each byte, writing the result to the `.bss` buffer at RVA
`0xD040`.

## Verification

The public script maps the PE into Unicorn at its original image base, executes
the original flag-construction function, and reads the output buffer:

```text
function start: 0x1400014A0
function stop:  0x1400014FF
buffer:         0x14000D040
```

## Script

```bash
python solve.py path/to/flag.exe
```

See [`solve.py`](solve.py).
