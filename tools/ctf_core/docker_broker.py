from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .evidence import EvidenceLedger
from .models import ToolError, envelope
from .task import TaskManager
from .util import PolicyError, project_root


def _settings() -> tuple[str, str | None]:
    root = project_root()
    url = os.environ.get("CTF_DOCKER_BROKER_URL", "http://127.0.0.1:8765")
    token_file = Path(
        os.environ.get("CTF_DOCKER_BROKER_TOKEN_FILE", str(root / "config" / "docker-broker-token"))
    )
    token = None
    if token_file.is_file():
        token = token_file.read_text(encoding="ascii").strip()
    return url.rstrip("/"), token


def _call(method: str, path: str, payload: dict[str, Any] | None = None, timeout: int = 30) -> dict[str, Any]:
    url, token = _settings()
    if not token:
        raise PolicyError("Docker broker token is missing; start the broker first")
    body = None
    headers = {"Authorization": f"Bearer {token}"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url + path, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        raise PolicyError(f"broker HTTP {exc.code}: {raw}") from exc
    except urllib.error.URLError as exc:
        raise PolicyError(f"broker unavailable: {exc}") from exc


def status(task_manager: TaskManager) -> dict[str, Any]:
    del task_manager
    started = time.monotonic()
    try:
        response = _call("GET", "/health", timeout=15)
        return envelope(
            "ctf_sandbox_status",
            ok=bool(response.get("ok")),
            duration_ms=int((time.monotonic() - started) * 1000),
            data=response,
        )
    except Exception as exc:
        return envelope(
            "ctf_sandbox_status",
            ok=False,
            duration_ms=int((time.monotonic() - started) * 1000),
            data={"configured": False},
            error=ToolError("BROKER_UNAVAILABLE", str(exc)),
        )


def create(task_manager: TaskManager, task_id: str, profile: str) -> dict[str, Any]:
    started = time.monotonic()
    try:
        task_manager.get_dir(task_id)
        response = _call("POST", "/v1/create", {"task_id": task_id, "profile": profile}, timeout=150)
        ledger = EvidenceLedger(task_manager.get_dir(task_id))
        ledger.event("sandbox_created", profile=profile, sandbox=response.get("data"))
        return envelope(
            "ctf_sandbox_create",
            ok=bool(response.get("ok")),
            task_id=task_id,
            duration_ms=int((time.monotonic() - started) * 1000),
            data=response.get("data"),
        )
    except Exception as exc:
        return envelope(
            "ctf_sandbox_create",
            ok=False,
            task_id=task_id,
            duration_ms=int((time.monotonic() - started) * 1000),
            error=ToolError("SANDBOX_CREATE_FAILED", str(exc)),
        )


def execute(
    task_manager: TaskManager,
    task_id: str,
    container_id: str,
    command: str,
    *,
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        task_dir = task_manager.get_dir(task_id)
        ledger = EvidenceLedger(task_dir)
        before = {
            path.relative_to(task_dir).as_posix()
            for path in (task_dir / "artifacts").rglob("*")
            if path.is_file()
        }
        response = _call(
            "POST",
            "/v1/exec",
            {
                "task_id": task_id,
                "container_id": container_id,
                "command": command,
                "timeout_seconds": timeout_seconds,
            },
            timeout=timeout_seconds + 20,
        )
        data = response.get("data") or {}
        ledger.command(
            ["sandbox-exec", profile_for_container(data), container_id],
            cwd=task_dir.as_posix(),
            exit_code=data.get("exit_code"),
            duration_ms=int(data.get("duration_ms", 0)),
            stdout_summary=str(data.get("stdout", "")),
            stderr_summary=str(data.get("stderr", "")),
            truncated=bool(data.get("truncated")),
        )
        after = {
            path.relative_to(task_dir).as_posix()
            for path in (task_dir / "artifacts").rglob("*")
            if path.is_file()
        }
        for relative in sorted(after - before):
            ledger.artifact(relative, kind="sandbox-artifact", source_tool="ctf_sandbox_exec")
        return envelope(
            "ctf_sandbox_exec",
            ok=bool(response.get("ok")) and bool(data.get("ok")),
            task_id=task_id,
            duration_ms=int((time.monotonic() - started) * 1000),
            exit_code=data.get("exit_code"),
            truncated=bool(data.get("truncated")),
            data=data,
            error=None
            if bool(data.get("ok"))
            else ToolError("SANDBOX_COMMAND_FAILED", data.get("stderr") or data.get("error") or "failed"),
        )
    except Exception as exc:
        return envelope(
            "ctf_sandbox_exec",
            ok=False,
            task_id=task_id,
            duration_ms=int((time.monotonic() - started) * 1000),
            error=ToolError("SANDBOX_EXEC_FAILED", str(exc)),
        )


def stop(task_manager: TaskManager, task_id: str, container_id: str) -> dict[str, Any]:
    started = time.monotonic()
    try:
        task_manager.get_dir(task_id)
        response = _call(
            "POST",
            "/v1/stop",
            {"task_id": task_id, "container_id": container_id},
            timeout=40,
        )
        EvidenceLedger(task_manager.get_dir(task_id)).event(
            "sandbox_stopped",
            container_id=container_id,
            result=response.get("data"),
        )
        return envelope(
            "ctf_sandbox_stop",
            ok=bool(response.get("ok")),
            task_id=task_id,
            duration_ms=int((time.monotonic() - started) * 1000),
            data=response.get("data"),
        )
    except Exception as exc:
        return envelope(
            "ctf_sandbox_stop",
            ok=False,
            task_id=task_id,
            duration_ms=int((time.monotonic() - started) * 1000),
            error=ToolError("SANDBOX_STOP_FAILED", str(exc)),
        )


def build(task_manager: TaskManager, profile: str, timeout_seconds: int = 1800) -> dict[str, Any]:
    del task_manager
    started = time.monotonic()
    try:
        response = _call(
            "POST",
            "/v1/build",
            {"profile": profile, "timeout_seconds": timeout_seconds},
            timeout=timeout_seconds + 30,
        )
        return envelope(
            "ctf_sandbox_build",
            ok=bool(response.get("ok")),
            duration_ms=int((time.monotonic() - started) * 1000),
            data=response.get("data"),
        )
    except Exception as exc:
        return envelope(
            "ctf_sandbox_build",
            ok=False,
            duration_ms=int((time.monotonic() - started) * 1000),
            error=ToolError("SANDBOX_BUILD_FAILED", str(exc)),
        )


def profile_for_container(data: dict[str, Any]) -> str:
    """Return a stable log label without trusting arbitrary model input."""
    image = str(data.get("image", ""))
    if ":" in image:
        return image.rsplit("/", 1)[-1].split(":", 1)[0]
    return "sandbox"
