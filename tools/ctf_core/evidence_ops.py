from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from .evidence import EvidenceLedger
from .models import ToolError, envelope
from .task import TaskManager
from .util import PolicyError, resolve_within


def _write_recorded_output(task_dir: Path, stem: str, content: str, source_tool: str) -> dict[str, Any] | None:
    if not content:
        return None
    artifact_dir = task_dir / "artifacts"
    artifact_dir.mkdir(exist_ok=True)
    path = artifact_dir / f"recorded-{stem}-{time.time_ns()}.txt"
    path.write_text(content, encoding="utf-8", newline="\n")
    return EvidenceLedger(task_dir).artifact(path, kind="text/plain", source_tool=source_tool)


def record_action(
    task_manager: TaskManager,
    task_id: str,
    *,
    description: str,
    command: str | list[str],
    cwd: str = "",
    exit_code: int | None = None,
    duration_ms: int = 0,
    stdout: str = "",
    stderr: str = "",
    truncated: bool = False,
    artifact_files: list[str] | None = None,
) -> dict[str, Any]:
    try:
        task_dir = task_manager.get_dir(task_id)
        ledger = EvidenceLedger(task_dir)
        command_parts = [command] if isinstance(command, str) else [str(item) for item in command]
        command_parts = command_parts[:200]
        if not description.strip():
            raise PolicyError("description must not be empty")
        if not command_parts or not any(part.strip() for part in command_parts):
            raise PolicyError("command must not be empty")
        artifacts: list[dict[str, Any]] = []
        stdout_record = _write_recorded_output(task_dir, "stdout", stdout[:2 * 1024 * 1024], "ctf_evidence_record")
        if stdout_record:
            artifacts.append(stdout_record)
        stderr_record = _write_recorded_output(task_dir, "stderr", stderr[:2 * 1024 * 1024], "ctf_evidence_record")
        if stderr_record:
            artifacts.append(stderr_record)
        for relative in artifact_files or []:
            path = resolve_within(task_dir, relative, must_exist=True)
            artifacts.append(ledger.artifact(path, kind="recorded-artifact", source_tool="ctf_evidence_record"))
        ledger.command(
            command_parts,
            cwd=cwd or task_dir.as_posix(),
            exit_code=exit_code,
            duration_ms=max(0, int(duration_ms)),
            stdout_summary=stdout,
            stderr_summary=stderr,
            truncated=truncated,
        )
        ledger.event(
            "agent_action",
            description=description.strip()[:4000],
            command=command_parts,
            artifacts=artifacts,
            source="agent-reported",
        )
        return envelope(
            "ctf_evidence_record",
            ok=True,
            task_id=task_id,
            data={
                "description": description.strip(),
                "command": command_parts,
                "artifacts": artifacts,
                "source": "agent-reported",
            },
            artifacts=artifacts,
        )
    except Exception as exc:
        return envelope(
            "ctf_evidence_record",
            ok=False,
            task_id=task_id,
            exit_code=1,
            error=ToolError("EVIDENCE_RECORD_FAILED", str(exc)),
        )


def register_artifact(
    task_manager: TaskManager,
    task_id: str,
    *,
    artifact_file: str,
    kind: str = "file",
    source_tool: str = "ctf_register_artifact",
) -> dict[str, Any]:
    try:
        task_dir = task_manager.get_dir(task_id)
        path = resolve_within(task_dir, artifact_file, must_exist=True)
        record = EvidenceLedger(task_dir).artifact(path, kind=kind, source_tool=source_tool)
        return envelope(
            "ctf_register_artifact",
            ok=True,
            task_id=task_id,
            data=record,
            artifacts=[record],
        )
    except Exception as exc:
        return envelope(
            "ctf_register_artifact",
            ok=False,
            task_id=task_id,
            exit_code=1,
            error=ToolError("ARTIFACT_REGISTER_FAILED", str(exc)),
        )
