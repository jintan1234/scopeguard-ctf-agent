from __future__ import annotations

import hashlib
import math
import mimetypes
import re
import shutil
import subprocess
import time
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

from .evidence import EvidenceLedger
from .flagops import discover_candidates
from .models import ToolError, envelope
from .task import TaskManager
from .util import PolicyError, project_root, resolve_within, sha256_file


MAX_HASH_BYTES = 2 * 1024 * 1024 * 1024
MAX_INSPECT_BYTES = 8 * 1024 * 1024


def _magic(head: bytes) -> list[str]:
    signatures = [
        (b"\x89PNG\r\n\x1a\n", "png"),
        (b"\xff\xd8\xff", "jpeg"),
        (b"GIF87a", "gif87a"),
        (b"GIF89a", "gif89a"),
        (b"BM", "bmp"),
        (b"%PDF-", "pdf"),
        (b"PK\x03\x04", "zip"),
        (b"PK\x05\x06", "zip-empty"),
        (b"7z\xbc\xaf\x27\x1c", "7z"),
        (b"Rar!\x1a\x07", "rar"),
        (b"\x1f\x8b", "gzip"),
        (b"\x7fELF", "elf"),
        (b"MZ", "pe"),
        (b"SQLite format 3\x00", "sqlite"),
        (b"\xd4\xc3\xb2\xa1", "pcap-little"),
        (b"\xa1\xb2\xc3\xd4", "pcap-big"),
        (b"\x0a\x0d\x0d\x0a", "pcapng"),
        (b"OggS", "ogg"),
        (b"RIFF", "riff"),
        (b"ID3", "mp3-id3"),
        (b"fLaC", "flac"),
    ]
    found = [name for signature, name in signatures if head.startswith(signature)]
    if "riff" in found and len(head) >= 12:
        kind = head[8:12]
        if kind == b"WAVE":
            found.append("wav")
        elif kind == b"AVI ":
            found.append("avi")
        elif kind == b"WEBP":
            found.append("webp")
    return found


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _printable_strings(data: bytes, minimum: int = 4, limit: int = 80) -> list[str]:
    pattern = re.compile(rb"[\x20-\x7e]{" + str(minimum).encode("ascii") + rb",}")
    values: list[str] = []
    for match in pattern.finditer(data):
        values.append(match.group(0).decode("ascii", "replace"))
        if len(values) >= limit:
            break
    return values


def _zip_members(path: Path, limit: int = 100) -> list[dict[str, Any]]:
    if not zipfile.is_zipfile(path):
        return []
    with zipfile.ZipFile(path) as archive:
        return [
            {
                "name": item.filename,
                "size": item.file_size,
                "compressed_size": item.compress_size,
                "encrypted": bool(item.flag_bits & 0x1),
                "is_dir": item.is_dir(),
            }
            for item in archive.infolist()[:limit]
        ]


def _resolve_task_file(task_dir: Path, value: str) -> Path:
    path = resolve_within(task_dir, value, must_exist=True)
    if not path.is_file():
        raise PolicyError(f"not a regular file: {value}")
    return path


def inspect_file(
    task_manager: TaskManager,
    task_id: str,
    file: str,
    *,
    max_strings: int = 80,
) -> dict[str, Any]:
    started = time.monotonic()
    start_wall = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    ledger: EvidenceLedger | None = None
    try:
        task_dir = task_manager.get_dir(task_id)
        ledger = EvidenceLedger(task_dir)
        path = _resolve_task_file(task_dir, file)
        size = path.stat().st_size
        if size > MAX_HASH_BYTES:
            raise PolicyError(f"file too large to hash safely: {size} bytes")
        with path.open("rb") as handle:
            head = handle.read(min(size, MAX_INSPECT_BYTES))
        sha256 = sha256_file(path)
        sha1 = hashlib.sha1()
        md5 = hashlib.md5()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                sha1.update(chunk)
                md5.update(chunk)
        detected = _magic(head[:64])
        strings = _printable_strings(head, limit=max_strings)
        payload = {
            "path": path.relative_to(task_dir).as_posix(),
            "size": size,
            "sha256": sha256,
            "sha1": sha1.hexdigest(),
            "md5": md5.hexdigest(),
            "magic": detected,
            "mime_guess": mimetypes.guess_type(path.name)[0],
            "header_hex": head[:64].hex(),
            "entropy_sampled": round(_entropy(head[: 1024 * 1024]), 4),
            "strings": strings,
            "flag_candidates": discover_candidates("\n".join(strings))[:100],
            "zip_members": _zip_members(path),
        }
        artifact = ledger.artifact(path, kind="file-inspection-subject", source_tool="ctf_file_inspect")
        ledger.event("file_inspected", file=payload["path"], sha256=sha256, size=size)
        ledger.command(
            ["internal:file-inspect", payload["path"]],
            cwd=task_dir.as_posix(),
            exit_code=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            stdout_summary=f"detected={','.join(detected) or 'unknown'} sha256={sha256}",
        )
        return envelope(
            "ctf_file_inspect",
            ok=True,
            task_id=task_id,
            started_at=start_wall,
            duration_ms=int((time.monotonic() - started) * 1000),
            data=payload,
            artifacts=[artifact],
        )
    except Exception as exc:
        if ledger is not None:
            ledger.event("tool_error", tool="ctf_file_inspect", error=str(exc))
        return envelope(
            "ctf_file_inspect",
            ok=False,
            task_id=task_id,
            started_at=start_wall,
            duration_ms=int((time.monotonic() - started) * 1000),
            exit_code=1,
            error=ToolError("FILE_INSPECT_FAILED", str(exc)),
        )


def find_tshark() -> str | None:
    found = shutil.which("tshark")
    if found:
        return found
    candidate = Path(r"C:\Program Files\Wireshark\tshark.exe")
    return str(candidate) if candidate.is_file() else None


def analyze_pcap(
    task_manager: TaskManager,
    task_id: str,
    file: str,
    *,
    display_filter: str | None = None,
    timeout_seconds: int = 60,
    max_output_bytes: int = 1024 * 1024,
) -> dict[str, Any]:
    started = time.monotonic()
    start_wall = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    ledger: EvidenceLedger | None = None
    try:
        task_dir = task_manager.get_dir(task_id)
        ledger = EvidenceLedger(task_dir)
        path = _resolve_task_file(task_dir, file)
        tshark = find_tshark()
        if not tshark:
            raise FileNotFoundError("tshark was not found")
        command = [tshark, "-r", str(path), "-q"]
        if display_filter:
            command.extend(["-Y", display_filter])
        command.extend(["-z", "io,phs"])
        completed = subprocess.run(
            command,
            cwd=task_dir,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
        stdout = completed.stdout[:max_output_bytes]
        stderr = completed.stderr[: max_output_bytes // 4]
        output_path = task_dir / "artifacts" / f"{path.stem}-tshark-protocol-hierarchy.txt"
        output_path.write_bytes(stdout)
        artifact = ledger.artifact(output_path, kind="text/plain", source_tool="ctf_analyze_pcap")
        ledger.command(
            command,
            cwd=task_dir.as_posix(),
            exit_code=completed.returncode,
            duration_ms=int((time.monotonic() - started) * 1000),
            stdout_summary=stdout.decode("utf-8", "replace"),
            stderr_summary=stderr.decode("utf-8", "replace"),
            truncated=len(completed.stdout) > len(stdout),
        )
        return envelope(
            "ctf_analyze_pcap",
            ok=completed.returncode == 0,
            task_id=task_id,
            started_at=start_wall,
            duration_ms=int((time.monotonic() - started) * 1000),
            exit_code=completed.returncode,
            truncated=len(completed.stdout) > len(stdout),
            data={
                "file": path.relative_to(task_dir).as_posix(),
                "tshark": tshark,
                "protocol_hierarchy": stdout.decode("utf-8", "replace"),
                "stderr": stderr.decode("utf-8", "replace"),
            },
            artifacts=[artifact],
            error=(
                None
                if completed.returncode == 0
                else ToolError("TSHARK_FAILED", "tshark returned a non-zero exit code")
            ),
        )
    except subprocess.TimeoutExpired:
        if ledger is not None:
            ledger.event("tool_error", tool="ctf_analyze_pcap", error="timeout")
        return envelope(
            "ctf_analyze_pcap",
            ok=False,
            task_id=task_id,
            started_at=start_wall,
            duration_ms=int((time.monotonic() - started) * 1000),
            exit_code=None,
            error=ToolError("TIMEOUT", f"tshark exceeded {timeout_seconds} seconds"),
        )
    except Exception as exc:
        if ledger is not None:
            ledger.event("tool_error", tool="ctf_analyze_pcap", error=str(exc))
        return envelope(
            "ctf_analyze_pcap",
            ok=False,
            task_id=task_id,
            started_at=start_wall,
            duration_ms=int((time.monotonic() - started) * 1000),
            exit_code=1,
            error=ToolError("PCAP_ANALYSIS_FAILED", str(exc)),
        )


def inspect_image(task_manager: TaskManager, task_id: str, file: str) -> dict[str, Any]:
    started = time.monotonic()
    start_wall = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    ledger: EvidenceLedger | None = None
    try:
        task_dir = task_manager.get_dir(task_id)
        ledger = EvidenceLedger(task_dir)
        path = _resolve_task_file(task_dir, file)
        base = inspect_file(task_manager, task_id, file, max_strings=40)
        if not base["ok"]:
            return base
        data = {
            "file": path.relative_to(task_dir).as_posix(),
            "format": (base["data"]["magic"] or ["unknown"])[0],
            "size": path.stat().st_size,
            "sha256": base["data"]["sha256"],
            "metadata": {},
            "pillow_available": False,
        }
        try:
            from PIL import Image  # type: ignore

            with Image.open(path) as image:
                data["pillow_available"] = True
                data["metadata"] = {
                    "width": image.width,
                    "height": image.height,
                    "mode": image.mode,
                    "format": image.format,
                    "info": {str(k): str(v) for k, v in image.info.items()},
                }
        except ImportError:
            data["metadata"] = {"note": "Pillow is not installed; only magic/header inspection ran"}
        except Exception as exc:
            data["metadata"] = {"note": f"Pillow could not parse the image: {exc}"}
        if ledger:
            ledger.event("image_inspected", **data)
            ledger.command(
                ["internal:image-inspect", data["file"]],
                cwd=task_dir.as_posix(),
                exit_code=0,
                duration_ms=int((time.monotonic() - started) * 1000),
                stdout_summary=f"format={data['format']} pillow={data['pillow_available']}",
            )
        return envelope(
            "ctf_inspect_image",
            ok=True,
            task_id=task_id,
            started_at=start_wall,
            duration_ms=int((time.monotonic() - started) * 1000),
            data=data,
        )
    except Exception as exc:
        if ledger is not None:
            ledger.event("tool_error", tool="ctf_inspect_image", error=str(exc))
        return envelope(
            "ctf_inspect_image",
            ok=False,
            task_id=task_id,
            started_at=start_wall,
            duration_ms=int((time.monotonic() - started) * 1000),
            exit_code=1,
            error=ToolError("IMAGE_INSPECTION_FAILED", str(exc)),
        )
