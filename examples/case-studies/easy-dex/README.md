# Case study: Android Native loader and protected DEX

This case study covers a NativeActivity APK with no root `classes.dex`.

```text
Target: offline Android APK
Flag: qwb{TH3y_Io<e_EACh_OTh3r_FOrEUER}
Assurance: reproducible_evidence
```

## Chain

1. The APK loads `libnative.so`.
2. Native code waits for 100 alternating accelerometer events in 10 seconds.
3. It reads an embedded payload at virtual address `0x7004`.
4. The payload is XORed in ten blocks with keys:

```text
0x09, 0x13, 0x1D, 0x27, 0x31,
0x3B, 0x45, 0x4F, 0x59, 0x59
```

5. The result is zlib-compressed DEX data.
6. The app writes the DEX and loads it through `DexClassLoader`.
7. The recovered DEX validates input through Twofish-256 in ECB mode.
8. The key comes from the `two_fish` Android resource.

## Recovery

```bash
python recover_easy_dex.py \
  path/to/libnative.so \
  recovered/classes.dex
```

Then:

```bash
apktool d -f -o apktool-out original.apk
jadx -d jadx-out recovered/classes.dex
```

## Verification

The verification script extracts:

- the 48-byte ciphertext from `MainActivity`;
- the resource string from `strings.xml`;
- the normalized 32-byte key;

and then performs decrypt plus re-encrypt:

```text
plaintext = Twofish.decrypt(ciphertext, key)
padded = plaintext + zero_padding
assert Twofish.encrypt(padded, key) == ciphertext
```

The verified Flag is `qwb{TH3y_Io<e_EACh_OTh3r_FOrEUER}`. See
[`recover_easy_dex.py`](recover_easy_dex.py) and
[`verify_twofish_flag.py`](verify_twofish_flag.py).

The verification script requires Linux with `libgcrypt`. On Windows, run it in
the analysis Docker profile instead of directly on the host.

## Lessons

- NativeActivity hides ordinary Java entry points.
- Sensor gates can be reversed statically.
- Protected DEX payloads often use reversible XOR plus compression.
- A decrypted printable string is weaker evidence than a complete re-encrypt
  round trip.
