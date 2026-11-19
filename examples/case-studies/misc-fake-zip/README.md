# Case study: fake-encrypted ZIP

Offline Misc challenge.

```text
Target: local flag.zip
Flag: flag{down!_good_flag}
Assurance: reproducible_evidence
```

## Why ordinary extraction fails

The ZIP central directory marks the entry encrypted, but the local file header
has general-purpose flags `0x0000`. The payload starting at offset 38 is a
normal raw DEFLATE stream, not an encrypted stream with a 12-byte encryption
header.

Tools therefore report:

- `Headers Error`
- `Encrypted = -`
- `file security status: encrypted`

## Correct path

Read the local payload and decompress it as raw DEFLATE:

```python
payload = data[38:38 + 21]
plain = zlib.decompress(payload, -15)
```

Result:

```text
flag{down!_good_flag}
```

See [`solve.py`](solve.py).
