---
name: ctf-misc
description: Use for CTF archives, encoded data, images, audio/video, PDF/Office, QR/OCR, file repair, binary blobs, steganography and miscellaneous format analysis.
---

# Misc and Steganography

## Triage

1. Run `ctf_file_inspect`.
2. Record file name, magic, hashes, entropy and notable strings.
3. Check whether the extension contradicts the magic.
4. Identify nesting: ZIP in PNG, PDF streams, appended archives, polyglots.
5. Preserve the original; write repaired/derived files under `artifacts/`.

## Archives

- List before extracting.
- Check encryption, comments, timestamps and unusual member names.
- Extract into a task-local directory.
- Avoid recursive decompression bombs; set file-count and expanded-size limits.
- Look for hidden files, alternate data in names, nested archives and CRC mismatches.

## Encodings

Maintain a short transformation chain and record every step. Common transformations:

- Base64/Base32/Base58/Base85
- Hex, URL, HTML entities
- ROT/Atbash/Morse/Bacon
- gzip/zlib/bzip2/xz
- XOR with single-byte or known key

Stop when output is structurally meaningful. Do not brute-force huge spaces without a hypothesis.

## Images

- Metadata and comments.
- PNG chunks, trailing bytes, dimensions/CRC anomalies.
- JPEG segments, EXIF, trailing data.
- Palette/LSB/stego tools.
- Palette order, frame delays and animation.
- OCR and QR decode.

Never trust the file extension. Use magic and parser errors.

## Audio/video

- `ffprobe` streams, metadata, duration and codecs.
- Spectrogram inspection.
- DTMF/Morse/modems/slow-scan TV as challenge hints suggest.
- Extract subtitle, attachment and metadata tracks.

## PDF / Office

- Extract text and attachments.
- Inspect objects, actions, macros and embedded files.
- Treat PDFs/Office files as untrusted; parse in an isolated environment when automation supports it.

## Evidence

Save the final decoded/extracted artifact and log the complete transformation command. A flag found only in transient stdout should still be written to a proof artifact before verification.
