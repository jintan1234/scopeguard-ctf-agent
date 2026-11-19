from __future__ import annotations

import dis
import importlib.util
import marshal
import shutil
import struct
import time
import zipfile
from pathlib import Path
from typing import Any

from .evidence import EvidenceLedger
from .models import ToolError, envelope
from .task import TaskManager
from .util import PolicyError, resolve_within


MAX_ARCHIVE_FILES = 2000
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024


def _safe_archive_target(root: Path, member: str) -> Path:
    destination = (root / member).resolve()
    root = root.resolve()
    if destination != root and root not in destination.parents:
        raise PolicyError(f"archive member escapes extraction root: {member}")
    return destination


def archive_inspect(
    task_manager: TaskManager,
    task_id: str,
    file: str,
    *,
    extract: bool = False,
) -> dict[str, Any]:
    started = time.monotonic()
    ledger: EvidenceLedger | None = None
    try:
        task_dir = task_manager.get_dir(task_id)
        ledger = EvidenceLedger(task_dir)
        path = resolve_within(task_dir, file, must_exist=True)
        if not zipfile.is_zipfile(path):
            seven = shutil.which("7z") or r"C:\Program Files\7-Zip\7z.exe"
            return envelope(
                "ctf_archive_inspect",
                ok=True,
                task_id=task_id,
                data={
                    "input": path.relative_to(task_dir).as_posix(),
                    "zip": False,
                    "seven_zip": Path(seven).is_file() if seven else False,
                    "note": "Non-ZIP archive. Use the installed 7-Zip CLI for listing/extraction.",
                },
            )
        extracted: list[dict[str, Any]] = []
        members: list[dict[str, Any]] = []
        output_root = task_dir / "artifacts" / f"{path.stem}-extracted"
        total = 0
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_FILES:
                raise PolicyError("archive contains too many members")
            for item in infos:
                member_record = {
                    "name": item.filename,
                    "size": item.file_size,
                    "compressed_size": item.compress_size,
                    "encrypted": bool(item.flag_bits & 0x1),
                    "is_dir": item.is_dir(),
                }
                members.append(member_record)
                if not extract or item.is_dir():
                    continue
                if item.flag_bits & 0x1:
                    raise PolicyError(f"encrypted member requires a password: {item.filename}")
                total += item.file_size
                if total > MAX_ARCHIVE_BYTES:
                    raise PolicyError("expanded archive size exceeds limit")
                destination = _safe_archive_target(output_root, item.filename)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(item) as source, destination.open("wb") as target:
                    shutil.copyfileobj(source, target)
                extracted.append(
                    {
                        "member": item.filename,
                        "output": destination.relative_to(task_dir).as_posix(),
                        "size": destination.stat().st_size,
                    }
                )
        artifacts = []
        if extract:
            manifest = task_dir / "artifacts" / f"{path.stem}-extracted-manifest.json"
            import json

            manifest.write_text(
                json.dumps({"members": members, "extracted": extracted}, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            artifacts.append(
                ledger.artifact(manifest, kind="application/json", source_tool="ctf_archive_inspect")
            )
        ledger.event(
            "archive_inspected",
            input=path.relative_to(task_dir).as_posix(),
            members=len(members),
            extracted=len(extracted),
        )
        return envelope(
            "ctf_archive_inspect",
            ok=True,
            task_id=task_id,
            duration_ms=int((time.monotonic() - started) * 1000),
            data={
                "input": path.relative_to(task_dir).as_posix(),
                "zip": True,
                "members": members,
                "extracted": extracted,
                "output_dir": output_root.relative_to(task_dir).as_posix() if extract else None,
            },
            artifacts=artifacts,
        )
    except Exception as exc:
        if ledger:
            ledger.event("tool_error", tool="ctf_archive_inspect", error=str(exc))
        return envelope(
            "ctf_archive_inspect",
            ok=False,
            task_id=task_id,
            exit_code=1,
            error=ToolError("ARCHIVE_INSPECTION_FAILED", str(exc)),
        )


def reverse_static(task_manager: TaskManager, task_id: str, file: str) -> dict[str, Any]:
    started = time.monotonic()
    ledger: EvidenceLedger | None = None
    try:
        task_dir = task_manager.get_dir(task_id)
        ledger = EvidenceLedger(task_dir)
        path = resolve_within(task_dir, file, must_exist=True)
        header = path.read_bytes()[:64]
        result: dict[str, Any] = {
            "input": path.relative_to(task_dir).as_posix(),
            "format": "unknown",
            "details": {},
        }
        if header.startswith(b"MZ"):
            import pefile

            pe = pefile.PE(str(path), fast_load=False)
            result["format"] = "pe"
            result["details"] = {
                "machine": hex(pe.FILE_HEADER.Machine),
                "timestamp": pe.FILE_HEADER.TimeDateStamp,
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "sections": [
                    {
                        "name": section.Name.rstrip(b"\x00").decode("latin-1", "replace"),
                        "virtual_address": hex(section.VirtualAddress),
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_size": section.SizeOfRawData,
                        "entropy": round(section.get_entropy(), 4),
                    }
                    for section in pe.sections
                ],
                "imports": sorted(
                    {
                        entry.dll.decode("latin-1", "replace")
                        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
                    }
                ),
            }
            pe.close()
        elif header.startswith(b"\x7fELF"):
            from elftools.elf.elffile import ELFFile

            with path.open("rb") as handle:
                elf = ELFFile(handle)
                result["format"] = "elf"
                result["details"] = {
                    "class": elf.elfclass,
                    "little_endian": elf.little_endian,
                    "machine": elf.header["e_machine"],
                    "type": elf.header["e_type"],
                    "entry": hex(elf.header["e_entry"]),
                    "sections": [
                        {
                            "name": section.name,
                            "type": section["sh_type"],
                            "size": section["sh_size"],
                        }
                        for section in elf.iter_sections()
                    ],
                }
        elif path.suffix.lower() == ".pyc" or header[:4] == importlib.util.MAGIC_NUMBER:
            result["format"] = "python-bytecode"
            if header[:4] != importlib.util.MAGIC_NUMBER:
                raise PolicyError(
                    "Python bytecode version does not match this interpreter; install xdis or use matching Python"
                )
            code = marshal.loads(path.read_bytes()[16:])
            instructions = [
                {
                    "offset": instruction.offset,
                    "opname": instruction.opname,
                    "arg": instruction.arg,
                    "argval": repr(instruction.argval),
                }
                for instruction in dis.get_instructions(code)
            ]
            constants: list[str] = []

            def walk(code_object: Any) -> None:
                for constant in code_object.co_consts:
                    if isinstance(constant, (str, bytes, int, float)):
                        constants.append(repr(constant))
                    elif hasattr(constant, "co_code"):
                        walk(constant)

            walk(code)
            result["details"] = {
                "code_name": code.co_name,
                "instructions": instructions[:2000],
                "constants": constants[:1000],
            }
        ledger.event("reverse_static", **result)
        artifact = task_dir / "artifacts" / f"{path.stem}-reverse-static.json"
        import json

        artifact.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        ledger.artifact(artifact, kind="application/json", source_tool="ctf_reverse_static")
        return envelope(
            "ctf_reverse_static",
            ok=True,
            task_id=task_id,
            duration_ms=int((time.monotonic() - started) * 1000),
            data=result,
            artifacts=[
                {
                    "path": artifact.relative_to(task_dir).as_posix(),
                    "kind": "application/json",
                }
            ],
        )
    except Exception as exc:
        if ledger:
            ledger.event("tool_error", tool="ctf_reverse_static", error=str(exc))
        return envelope(
            "ctf_reverse_static",
            ok=False,
            task_id=task_id,
            exit_code=1,
            error=ToolError("REVERSE_STATIC_FAILED", str(exc)),
        )
