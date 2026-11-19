from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote_to_bytes

from .evidence import EvidenceLedger
from .flagops import discover_candidates
from .models import ToolError, envelope
from .task import TaskManager
from .util import PolicyError, resolve_within


MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_NODES = 400
MAX_DEPTH = 4


@dataclass(frozen=True)
class Transform:
    name: str
    args: tuple[Any, ...]


def _text_score(data: bytes) -> float:
    if not data:
        return 0.0
    printable_ascii = sum(
        1
        for value in data
        if value in (9, 10, 13) or 32 <= value <= 126
    )
    alpha = sum(
        chr(value).isalnum() or chr(value) in "{}_- .:/"
        for value in data
        if value < 128
    )
    return round(0.8 * printable_ascii / len(data) + 0.2 * alpha / len(data), 4)


def _to_text(data: bytes) -> str:
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", "replace")


def _apply(data: bytes, transform: Transform) -> bytes:
    name = transform.name
    if name == "base64":
        compact = re.sub(rb"\s+", b"", data)
        compact += b"=" * (-len(compact) % 4)
        return base64.b64decode(compact, validate=True)
    if name == "base32":
        compact = re.sub(rb"\s+", b"", data).upper()
        compact += b"=" * (-len(compact) % 8)
        return base64.b32decode(compact, casefold=True)
    if name == "base85":
        return base64.b85decode(data)
    if name == "hex":
        compact = re.sub(rb"[\s:]", b"", data)
        return bytes.fromhex(compact.decode("ascii"))
    if name == "url":
        return unquote_to_bytes(data.decode("ascii"))
    if name == "rot13":
        return codecs.decode(data.decode("utf-8"), "rot_13").encode("utf-8")
    if name == "reverse":
        return data[::-1]
    if name == "atbash":
        text = data.decode("latin-1")
        converted = "".join(
            chr(ord("z") - (ord(char.lower()) - ord("a")))
            if char.isascii() and char.isalpha()
            else char
            for char in text
        )
        return converted.encode("latin-1")
    if name == "xor":
        key = int(transform.args[0])
        return bytes(value ^ key for value in data)
    if name == "utf16le":
        return data.decode("utf-16-le").encode("utf-8")
    raise PolicyError(f"unknown transform: {name}")


def _possible_transforms(data: bytes, depth: int) -> list[Transform]:
    stripped = re.sub(rb"\s+", b"", data)
    values: list[Transform] = []
    text = data.decode("latin-1", "ignore")
    if stripped and len(stripped) % 2 == 0 and re.fullmatch(rb"[0-9A-Fa-f:]+", stripped):
        return [Transform("hex", ())]
    if stripped and re.fullmatch(rb"[A-Z2-7=]+", stripped):
        return [Transform("base32", ())]
    if stripped and re.fullmatch(rb"[A-Za-z0-9+/=]+", stripped):
        return [Transform("base64", ())]
    mixed_binary = _text_score(data) < 0.98 or any(value < 9 or 13 < value < 32 for value in data)
    if depth <= 1 and mixed_binary:
        values.extend(Transform("xor", (key,)) for key in range(1, 256))
    if "%" in text or "+" in text:
        values.append(Transform("url", ()))
    if re.search(r"[A-Za-z]", text):
        values.append(Transform("rot13", ()))
        values.append(Transform("atbash", ()))
    if len(data) > 1:
        values.append(Transform("reverse", ()))
    return values


def _transform_steps(data: bytes, transforms: list[str], xor_key: int | None = None) -> dict[str, Any]:
    current = data
    steps: list[dict[str, Any]] = []
    for name in transforms:
        transform = Transform("xor", (xor_key,)) if name == "xor" else Transform(name, ())
        current = _apply(current, transform)
        steps.append(
            {
                "operation": name,
                "xor_key": xor_key if name == "xor" else None,
                "preview": _to_text(current)[:500],
                "sha256": hashlib.sha256(current).hexdigest(),
            }
        )
    return {
        "data": current,
        "steps": steps,
        "score": _text_score(current),
        "text": _to_text(current),
        "flags": discover_candidates(_to_text(current)),
    }


def auto_decode(
    task_manager: TaskManager,
    task_id: str,
    file: str,
    *,
    operations: list[str] | None = None,
    xor_key: int | None = None,
    max_depth: int = MAX_DEPTH,
    max_candidates: int = 20,
) -> dict[str, Any]:
    started = time.monotonic()
    ledger: EvidenceLedger | None = None
    try:
        task_dir = task_manager.get_dir(task_id)
        ledger = EvidenceLedger(task_dir)
        path = resolve_within(task_dir, file, must_exist=True)
        if not path.is_file():
            raise PolicyError("crypto input must be a file")
        data = path.read_bytes()
        if len(data) > MAX_INPUT_BYTES:
            raise PolicyError(f"crypto input exceeds {MAX_INPUT_BYTES} bytes")
        if operations:
            result = _transform_steps(data, operations, xor_key)
            candidates = [result]
        else:
            queue: list[tuple[bytes, list[Transform]]] = [(data, [])]
            seen = {hashlib.sha256(data).digest()}
            candidates: list[dict[str, Any]] = []
            processed = 0
            while queue and processed < MAX_NODES:
                current, history = queue.pop(0)
                processed += 1
                text = _to_text(current)
                flags = discover_candidates(text)
                score = _text_score(current)
                if history and (flags or score >= 0.85):
                    step_previews: list[dict[str, Any]] = []
                    preview_data = data
                    for item in history:
                        preview_data = _apply(preview_data, item)
                        step_previews.append(
                            {
                                "operation": item.name,
                                "argument": item.args[0] if item.args else None,
                                "preview": _to_text(preview_data)[:160],
                            }
                        )
                    candidates.append(
                        {
                            "data": current,
                            "steps": step_previews,
                            "score": score,
                            "text": text,
                            "flags": flags,
                        }
                    )
                if len(history) >= max_depth:
                    continue
                for transform in _possible_transforms(current, len(history)):
                    try:
                        transformed = _apply(current, transform)
                    except (ValueError, binascii.Error, UnicodeError):
                        continue
                    if not transformed or len(transformed) > MAX_INPUT_BYTES:
                        continue
                    digest = hashlib.sha256(transformed).digest()
                    if digest in seen:
                        continue
                    seen.add(digest)
                    queue.append((transformed, [*history, transform]))
            candidates.sort(
                key=lambda item: (
                    bool(item["flags"]),
                    item["score"],
                    -len(item["steps"]),
                ),
                reverse=True,
            )
            candidates = candidates[:max_candidates]
        compact = []
        for index, item in enumerate(candidates, 1):
            compact.append(
                {
                    "rank": index,
                    "score": item["score"],
                    "text_preview": item["text"][:2000],
                    "flags": item["flags"],
                    "steps": item["steps"],
                    "sha256": hashlib.sha256(item["data"]).hexdigest(),
                }
            )
        artifact_path = task_dir / "artifacts" / f"{path.stem}-decode-candidates.json"
        import json

        artifact_path.write_text(json.dumps(compact, indent=2, ensure_ascii=False), encoding="utf-8")
        artifact = ledger.artifact(artifact_path, kind="application/json", source_tool="ctf_auto_decode")
        ledger.command(
            ["internal:auto-decode", path.name],
            cwd=task_dir.as_posix(),
            exit_code=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            stdout_summary=f"candidates={len(compact)}",
        )
        return envelope(
            "ctf_auto_decode",
            ok=bool(compact),
            task_id=task_id,
            duration_ms=int((time.monotonic() - started) * 1000),
            data={"input": path.relative_to(task_dir).as_posix(), "candidates": compact},
            artifacts=[artifact],
            warnings=[] if compact else ["No plausible decoding chain was found."],
            error=None if compact else ToolError("NO_DECODE_CANDIDATE", "no candidate was found"),
        )
    except Exception as exc:
        if ledger:
            ledger.event("tool_error", tool="ctf_auto_decode", error=str(exc))
        return envelope(
            "ctf_auto_decode",
            ok=False,
            task_id=task_id,
            exit_code=1,
            error=ToolError("DECODE_FAILED", str(exc)),
        )
