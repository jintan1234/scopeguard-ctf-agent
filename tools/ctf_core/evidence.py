from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import utc_now
from .util import append_jsonl, resolve_within, sha256_file


class EvidenceLedger:
    def __init__(self, task_dir: Path):
        self.task_dir = task_dir.resolve()
        self.events_path = self.task_dir / "evidence" / "events.jsonl"
        self.commands_path = self.task_dir / "evidence" / "commands.jsonl"

    def event(self, event_type: str, **data: Any) -> dict[str, Any]:
        event = {"timestamp": utc_now(), "type": event_type, **data}
        append_jsonl(self.events_path, event)
        return event

    def command(
        self,
        command: list[str],
        *,
        cwd: str,
        exit_code: int | None,
        duration_ms: int,
        stdout_summary: str = "",
        stderr_summary: str = "",
        truncated: bool = False,
    ) -> dict[str, Any]:
        event = {
            "timestamp": utc_now(),
            "type": "command",
            "command": command,
            "cwd": cwd,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "stdout_summary": stdout_summary[:4000],
            "stderr_summary": stderr_summary[:4000],
            "truncated": truncated,
        }
        append_jsonl(self.commands_path, event)
        append_jsonl(self.events_path, event)
        return event

    def artifact(self, path: str | Path, *, kind: str, source_tool: str) -> dict[str, Any]:
        resolved = resolve_within(self.task_dir, path, must_exist=True)
        if not resolved.is_file():
            raise ValueError(f"artifact is not a file: {resolved}")
        record = {
            "path": resolved.relative_to(self.task_dir).as_posix(),
            "sha256": sha256_file(resolved),
            "size": resolved.stat().st_size,
            "kind": kind,
            "source_tool": source_tool,
        }
        self.event("artifact", **record)
        return record
