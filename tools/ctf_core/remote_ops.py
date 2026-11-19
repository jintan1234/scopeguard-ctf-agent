from __future__ import annotations

import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .evidence import EvidenceLedger
from .models import ToolError, envelope
from .scope import ScopePolicy
from .task import TaskManager
from .util import PolicyError, redact_url


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
DESTRUCTIVE_PATTERNS = (
    re.compile(r"(^|[;&|]\s*)rm\s+(?:-[^\s]*r|-[^\s]*f|--recursive|--force)", re.IGNORECASE),
    re.compile(r"(^|[;&|]\s*)(shutdown|reboot|poweroff|halt)\b", re.IGNORECASE),
    re.compile(r"(^|[;&|]\s*)(mkfs|fdisk|parted)\b", re.IGNORECASE),
    re.compile(r"(^|[;&|]\s*)dd\s+.*\bof=", re.IGNORECASE),
    re.compile(r":\(\)\s*\{\s*:\|:&\s*\};:", re.IGNORECASE),
    re.compile(r"(^|[;&|]\s*)(userdel|groupdel)\b", re.IGNORECASE),
    re.compile(r"(^|[;&|]\s*)iptables\s+-F\b", re.IGNORECASE),
)


def build_ssh_command(
    *,
    host: str,
    port: int,
    username: str,
    command: str,
    identity_file: str | None = None,
    known_hosts_file: str | None = None,
) -> list[str]:
    ssh = shutil.which("ssh.exe") or shutil.which("ssh")
    if not ssh:
        raise PolicyError("OpenSSH client is not installed")
    if not USERNAME_PATTERN.fullmatch(username):
        raise PolicyError("invalid SSH username")
    args = [
        ssh,
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "StrictHostKeyChecking=yes",
        "-p",
        str(port),
    ]
    if identity_file:
        identity = Path(identity_file).expanduser().resolve(strict=True)
        if not identity.is_file():
            raise PolicyError("SSH identity file is not a regular file")
        args.extend(["-i", str(identity)])
    if known_hosts_file:
        known_hosts = Path(known_hosts_file).expanduser().resolve(strict=True)
        if not known_hosts.is_file():
            raise PolicyError("SSH known_hosts file is not a regular file")
        args.extend(["-o", f"UserKnownHostsFile={known_hosts}"])
    args.extend([f"{username}@{host}", command])
    return args


def build_remote_http_command(
    *,
    url: str,
    method: str,
    headers: dict[str, str] | None,
    body: str | None,
    timeout_seconds: int,
) -> str:
    method = method.upper()
    if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        raise PolicyError(f"remote HTTP method is not allowed: {method}")
    args = [
        "curl",
        "--silent",
        "--show-error",
        "--max-time",
        str(max(1, min(timeout_seconds, 300))),
        "--request",
        method,
        "--dump-header",
        "-",
    ]
    for name, value in (headers or {}).items():
        if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}", name):
            raise PolicyError(f"invalid remote HTTP header name: {name!r}")
        if "\r" in value or "\n" in value:
            raise PolicyError("remote HTTP header values must not contain newlines")
        args.extend(["--header", f"{name}: {value}"])
    if body is not None:
        args.extend(["--data-binary", body])
    args.append(url)
    return " ".join(shlex.quote(value) for value in args)


def execute_ssh(
    task_manager: TaskManager,
    task_id: str,
    *,
    host: str,
    username: str,
    command: str,
    port: int = 22,
    identity_file: str | None = None,
    known_hosts_file: str | None = None,
    timeout_seconds: int = 60,
    destructive_confirmed: bool = False,
    source_tool: str = "ctf_remote_exec",
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        task_dir = task_manager.get_dir(task_id)
        policy = ScopePolicy.from_task(task_dir)
        checked = policy.validate_endpoint(host, port)
        if not command.strip() or len(command) > 65536:
            raise PolicyError("remote command is empty or too long")
        if any(pattern.search(command) for pattern in DESTRUCTIVE_PATTERNS) and not destructive_confirmed:
            raise PolicyError("destructive remote command requires destructive_confirmed=true")
        timeout_seconds = max(1, min(int(timeout_seconds), 300))
        local_command = build_ssh_command(
            host=str(checked["host"]),
            port=int(checked["port"]),
            username=username,
            command=command,
            identity_file=identity_file,
            known_hosts_file=known_hosts_file,
        )
        completed = subprocess.run(
            local_command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
        stdout = completed.stdout[:2 * 1024 * 1024]
        stderr = completed.stderr[:2 * 1024 * 1024]
        ledger = EvidenceLedger(task_dir)
        artifacts = []
        for suffix, content in (("stdout", stdout), ("stderr", stderr)):
            if content:
                path = task_dir / "artifacts" / f"remote-{suffix}-{time.time_ns()}.txt"
                path.write_text(content, encoding="utf-8", newline="\n")
                artifacts.append(ledger.artifact(path, kind="text/plain", source_tool=source_tool))
        ledger.command(
            ["ssh", f"{username}@{checked['host']}", f"port={checked['port']}", command],
            cwd=task_dir.as_posix(),
            exit_code=completed.returncode,
            duration_ms=int((time.monotonic() - started) * 1000),
            stdout_summary=stdout,
            stderr_summary=stderr,
            truncated=len(completed.stdout) > len(stdout) or len(completed.stderr) > len(stderr),
        )
        return envelope(
            source_tool,
            ok=completed.returncode == 0,
            task_id=task_id,
            duration_ms=int((time.monotonic() - started) * 1000),
            exit_code=completed.returncode,
            data={
                "host": checked["host"],
                "port": checked["port"],
                "username": username,
                "command": command,
                "stdout": stdout,
                "stderr": stderr,
            },
            artifacts=artifacts,
            error=None
            if completed.returncode == 0
            else ToolError("REMOTE_COMMAND_FAILED", stderr or f"ssh exited {completed.returncode}"),
        )
    except subprocess.TimeoutExpired as exc:
        return envelope(
            source_tool,
            ok=False,
            task_id=task_id,
            duration_ms=int((time.monotonic() - started) * 1000),
            error=ToolError("REMOTE_TIMEOUT", f"remote command timed out after {timeout_seconds}s", retryable=True),
        )
    except Exception as exc:
        return envelope(
            source_tool,
            ok=False,
            task_id=task_id,
            duration_ms=int((time.monotonic() - started) * 1000),
            error=ToolError("REMOTE_EXEC_FAILED", str(exc)),
        )


def execute_remote_http(
    task_manager: TaskManager,
    task_id: str,
    *,
    ssh_host: str,
    ssh_username: str,
    ssh_port: int,
    target_url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    identity_file: str | None = None,
    known_hosts_file: str | None = None,
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    try:
        task_dir = task_manager.get_dir(task_id)
        ScopePolicy.from_task(task_dir).validate_url(target_url)
        remote_command = build_remote_http_command(
            url=target_url,
            method=method,
            headers=headers,
            body=body,
            timeout_seconds=timeout_seconds,
        )
        result = execute_ssh(
            task_manager,
            task_id,
            host=ssh_host,
            username=ssh_username,
            command=remote_command,
            port=ssh_port,
            identity_file=identity_file,
            known_hosts_file=known_hosts_file,
            timeout_seconds=timeout_seconds,
            source_tool="ctf_remote_http",
        )
        result["tool"] = "ctf_remote_http"
        if isinstance(result.get("data"), dict):
            result["data"]["target_url"] = redact_url(target_url)
            result["data"]["method"] = method.upper()
        return result
    except Exception as exc:
        return envelope(
            "ctf_remote_http",
            ok=False,
            task_id=task_id,
            error=ToolError("REMOTE_HTTP_FAILED", str(exc)),
        )
