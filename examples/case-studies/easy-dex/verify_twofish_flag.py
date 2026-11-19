#!/usr/bin/env python3
"""Recover and verify a Twofish-256 ECB protected Flag."""

from __future__ import annotations

import ctypes
import ctypes.util
import pathlib
import re
import sys


class GcryptTwofish:
    GCRY_CIPHER_MODE_ECB = 1

    def __init__(self) -> None:
        library_name = ctypes.util.find_library("gcrypt")
        if not library_name:
            raise RuntimeError("libgcrypt is unavailable")
        self.lib = ctypes.CDLL(library_name)
        self.lib.gcry_check_version.restype = ctypes.c_char_p
        self.lib.gcry_cipher_map_name.restype = ctypes.c_int
        self.lib.gcry_cipher_open.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint,
        ]
        self.lib.gcry_cipher_setkey.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        self.lib.gcry_cipher_decrypt.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        self.lib.gcry_cipher_encrypt.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        self.lib.gcry_cipher_close.argtypes = [ctypes.c_void_p]
        self.lib.gcry_check_version(None)
        self.algorithm = self.lib.gcry_cipher_map_name(b"TWOFISH")
        if not self.algorithm:
            raise RuntimeError("libgcrypt does not expose TWOFISH")

    def crypt(self, key: bytes, data: bytes, *, decrypt: bool) -> bytes:
        handle = ctypes.c_void_p()
        if self.lib.gcry_cipher_open(
            ctypes.byref(handle),
            self.algorithm,
            self.GCRY_CIPHER_MODE_ECB,
            0,
        ):
            raise RuntimeError("gcry_cipher_open failed")
        try:
            if self.lib.gcry_cipher_setkey(handle, key, len(key)):
                raise RuntimeError("gcry_cipher_setkey failed")
            output = ctypes.create_string_buffer(len(data))
            source = ctypes.create_string_buffer(data, len(data))
            function = (
                self.lib.gcry_cipher_decrypt
                if decrypt
                else self.lib.gcry_cipher_encrypt
            )
            if function(handle, output, len(data), source, len(data)):
                raise RuntimeError("gcry cipher operation failed")
            return output.raw
        finally:
            self.lib.gcry_cipher_close(handle)


def normalize_java_key(raw_key: bytes) -> bytes:
    if len(raw_key) > 32 or len(raw_key) % 8 != 0:
        length = min(len(raw_key), 32)
        length += (1 if length & 7 else 0) * 8
        return raw_key[:length]
    return raw_key


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: verify_twofish_flag.py "
            "<MainActivity.java> <strings.xml>"
        )
        return 2

    main_activity = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    strings_xml = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")

    cipher_match = re.search(
        r"private static byte\[\] m = \{(.*?)\};",
        main_activity,
        re.DOTALL,
    )
    key_match = re.search(
        r'<string name="two_fish">(.*?)</string>',
        strings_xml,
        re.DOTALL,
    )
    if not cipher_match or not key_match:
        raise SystemExit("ciphertext or key resource not found")

    ciphertext = bytes(
        int(value.strip()) & 0xFF
        for value in cipher_match.group(1).split(",")
        if value.strip()
    )
    raw_key = key_match.group(1).encode("utf-8")
    key = normalize_java_key(raw_key)

    if len(ciphertext) % 16 or len(key) != 32:
        raise SystemExit("unexpected block or key size")

    twofish = GcryptTwofish()
    plaintext = twofish.crypt(key, ciphertext, decrypt=True)

    start = plaintext.find(b"flag{")
    if start < 0:
        start = plaintext.find(b"FLAG{")
    if start < 0:
        raise SystemExit("no Flag wrapper found in plaintext")
    end = plaintext.find(b"}", start)
    if end < 0:
        raise SystemExit("unterminated Flag")

    flag = plaintext[start : end + 1]
    padded = flag + bytes((-len(flag)) % 16)
    roundtrip = twofish.crypt(key, padded, decrypt=False)

    print(f"key_bytes_used={len(key)}")
    print(f"ciphertext_hex={ciphertext.hex()}")
    print(f"plaintext_hex={plaintext.hex()}")
    print(f"flag={flag.decode('ascii', errors='replace')}")
    print(f"roundtrip_matches={roundtrip == ciphertext}")
    return 0 if roundtrip == ciphertext else 1


if __name__ == "__main__":
    raise SystemExit(main())
