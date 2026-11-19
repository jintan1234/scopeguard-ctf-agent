# Sandbox images

## Profiles

| Profile | Base | Network at runtime | Purpose |
| --- | --- | --- | --- |
| analysis | Ubuntu 24.04 | none | misc, crypto, PCAP, basic reverse, stego |
| pwn | analysis | none | native exploit development and local binaries |
| reverse | analysis | none | reverse tooling requiring Java |
| web | analysis | none | isolated request generation tools |
| crypto | analysis | none | SageMath and heavier cryptography work |
| remote | analysis | none | offline X11/RDP/VNC capture and OCR tooling |

The Broker forces `--network none` for every profile in this phase. Network-enabled exploit profiles require a separate authorized target policy and are not silently enabled.

## Build order

```text
analysis
  -> pwn
  -> reverse
  -> web
  -> remote
  -> crypto (official SageMath image)
```

The broker builds only fixed Dockerfile paths and fixed image names.

## Analysis image contents

- file/binutils/strings/xxd
- 7-Zip, ZIP
- binwalk, foremost
- exiftool, ImageMagick, pngcheck
- steghide
- tshark
- Sleuth Kit
- ffmpeg
- Tesseract
- FreeRDP, Xvfb, xdotool, xclip, x11vnc, TigerVNC and scrot
- hashcat and John the Ripper
- YARA
- gdb, strace, ltrace, C/C++ build tools
- Python pwntools, PyCryptodome, sympy, z3, Capstone, pyelftools, pefile, scapy, Volatility 3

Ghidra, JADX, GEF, Nuclei, Feroxbuster, httpx/Katana, Chisel and Ligolo-ng
are provided through the broker's read-only `/opt/ctf-tools` mount from
`tool-runtime`. They are intentionally not committed because the combined
runtime is hundreds of megabytes. Install only the tools you need and place
them under `tool-runtime/`, or omit that mount and use the profile's built-in
tools.

The analysis image vendors the checksum-pinned StegSeek source archive under
`docker/analysis/third_party/` so the base image can build offline.

## Size

The analysis image is built and verified. The SageMath image is approximately
1.5 GB and is also kept in Docker's E-drive-backed engine rather than in the
project venv.
