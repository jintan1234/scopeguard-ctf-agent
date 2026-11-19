from __future__ import annotations

import time
from typing import Any

from .docker_broker import _call
from .models import ToolError, envelope
from .task import TaskManager


def _request(tool: str, path: str, payload: dict[str, Any], timeout: int) -> dict[str, Any]:
    started = time.monotonic()
    try:
        response = _call("POST", path, payload, timeout=timeout)
        return envelope(
            tool,
            ok=bool(response.get("ok")),
            duration_ms=int((time.monotonic() - started) * 1000),
            data=response.get("data"),
        )
    except Exception as exc:
        return envelope(
            tool,
            ok=False,
            duration_ms=int((time.monotonic() - started) * 1000),
            error=ToolError("LAB_OPERATION_FAILED", str(exc)),
        )


def build(task_manager: TaskManager, lab: str, timeout_seconds: int = 1800) -> dict[str, Any]:
    del task_manager
    return _request(
        "ctf_lab_build",
        "/v1/build",
        {"profile": lab, "timeout_seconds": timeout_seconds},
        timeout_seconds + 30,
    )


def start(task_manager: TaskManager, lab: str, host_port: int = 3000) -> dict[str, Any]:
    del task_manager
    return _request(
        "ctf_lab_start",
        "/v1/lab/start",
        {"lab": lab, "host_port": host_port},
        150,
    )


def stop(task_manager: TaskManager, lab: str) -> dict[str, Any]:
    del task_manager
    return _request("ctf_lab_stop", "/v1/lab/stop", {"lab": lab}, 90)


def status(task_manager: TaskManager, lab: str) -> dict[str, Any]:
    del task_manager
    return _request("ctf_lab_status", "/v1/lab/status", {"lab": lab}, 30)
