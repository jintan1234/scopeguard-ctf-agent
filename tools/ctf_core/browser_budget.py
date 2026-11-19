from __future__ import annotations

import json
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from .evidence import EvidenceLedger
from .task import TaskManager
from .util import project_root, read_json


SENSITIVE_KEYS = {"password", "token", "secret", "authorization", "cookie", "api_key", "apikey"}


def _redact(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "<depth-limit>"
    if isinstance(value, dict):
        result = {}
        for key, item in list(value.items())[:100]:
            if str(key).lower() in SENSITIVE_KEYS:
                result[str(key)] = "<redacted>"
            else:
                result[str(key)] = _redact(item, depth + 1)
        return result
    if isinstance(value, list):
        return [_redact(item, depth + 1) for item in value[:100]]
    if isinstance(value, str):
        return value[:500]
    return value


def _active_task_id(root: Path) -> str | None:
    path = root / "challenges" / "current" / "active-scope.json"
    try:
        scope = read_json(path)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    task_id = str(scope.get("task_id", ""))
    return task_id or None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        root = project_root()
        tasks = TaskManager(root)
        task_id = _active_task_id(root)
        if not task_id:
            result = {
                "allowed": False,
                "code": "NO_ACTIVE_TASK",
                "message": "No authorized task is active; browser tools are blocked.",
            }
            print(json.dumps(result, ensure_ascii=False))
            return 0
        action = str(payload.get("action", ""))
        tool_name = str(payload.get("tool_name", ""))
        arguments = payload.get("arguments") or {}
        if action == "begin":
            decision = tasks.begin_tool_call(
                task_id,
                f"playwright:{tool_name}",
                arguments,
            )
            print(json.dumps({"task_id": task_id, **decision}, ensure_ascii=False))
            return 0
        if action == "finish":
            ok = bool(payload.get("ok"))
            task_dir = tasks.get_dir(task_id)
            tasks.finish_tool_call(task_id, f"playwright:{tool_name}", ok=ok)
            ledger = EvidenceLedger(task_dir)
            artifact_records = []
            started_at_ms = float(payload.get("started_at_ms") or 0)
            output_dir = root / "challenges" / "current" / "browser-output"
            if started_at_ms > 0 and output_dir.is_dir():
                threshold = started_at_ms / 1000.0 - 1.0
                destination_dir = task_dir / "artifacts" / "browser-evidence"
                candidates = sorted(
                    (
                        path
                        for path in output_dir.rglob("*")
                        if path.is_file()
                        and path.stat().st_size <= 64 * 1024 * 1024
                        and path.stat().st_mtime >= threshold
                    ),
                    key=lambda path: path.stat().st_mtime,
                )[:20]
                for index, source in enumerate(candidates, 1):
                    destination_dir.mkdir(parents=True, exist_ok=True)
                    destination = destination_dir / (
                        f"{int(started_at_ms)}-{index:02d}-{source.name}"
                    )
                    shutil.copy2(source, destination)
                    artifact_records.append(
                        ledger.artifact(
                            destination,
                            kind="browser-artifact",
                            source_tool="playwright-mcp",
                        )
                    )
            ledger.event(
                "browser_tool_call",
                tool=tool_name,
                arguments=_redact(arguments),
                ok=ok,
                result_summary=str(payload.get("result_summary", ""))[:4000],
                artifacts=artifact_records,
            )
            print(
                json.dumps(
                    {
                        "ok": True,
                        "task_id": task_id,
                        "artifacts": artifact_records,
                    },
                    ensure_ascii=False,
                )
            )
            return 0
        raise ValueError(f"unknown browser budget action: {action}")
    except Exception as exc:
        print(json.dumps({"allowed": False, "code": "BROWSER_BUDGET_FAILED", "message": str(exc)}))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
