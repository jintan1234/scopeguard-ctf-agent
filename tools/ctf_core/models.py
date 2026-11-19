from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ToolError:
    code: str
    message: str
    retryable: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "details": self.details,
        }


def envelope(
    tool: str,
    *,
    ok: bool,
    task_id: str | None = None,
    started_at: str | None = None,
    duration_ms: int = 0,
    exit_code: int | None = 0,
    truncated: bool = False,
    data: Any = None,
    artifacts: list[dict[str, Any]] | None = None,
    warnings: list[str] | None = None,
    error: ToolError | None = None,
    next_actions: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "ok": ok,
        "tool": tool,
        "task_id": task_id,
        "started_at": started_at or utc_now(),
        "duration_ms": duration_ms,
        "exit_code": exit_code,
        "truncated": truncated,
        "data": data,
        "artifacts": artifacts or [],
        "warnings": warnings or [],
        "error": error.to_dict() if error else None,
        "next_actions": next_actions or [],
    }
