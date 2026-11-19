from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


MAX_BODY_BYTES = 64 * 1024
MAX_COMMAND_CHARS = 64 * 1024
TASK_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$")
CONTAINER_RE = re.compile(r"^(?:[0-9a-f]{12,64}|ctf-agent-[0-9a-f-]{9,})$")
PROFILE_DEFAULT_IMAGES = {
    "analysis": "ctf-agent/analysis:0.2",
    "reverse": "ctf-agent/reverse:0.2",
    "pwn": "ctf-agent/pwn:0.2",
    "web": "ctf-agent/web:0.2",
    "crypto": "ctf-agent/crypto:0.2",
    "remote": "ctf-agent/remote:0.2",
    "juice-shop": "ctf-agent/juice-shop:0.1",
}
SANDBOX_PROFILES = {"analysis", "reverse", "pwn", "web", "crypto", "remote"}
LABS = {
    "juice-shop": {
        "profile": "juice-shop",
        "container_port": 3000,
        "container_name": "ctf-lab-juice-shop",
    }
}


class BrokerError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


def utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def ensure_token(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        token = path.read_text(encoding="ascii").strip()
        if len(token) >= 32:
            return token
    token = secrets.token_urlsafe(48)
    fd = os.open(str(path), os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(token + "\n")
    return token


def resolve_task_dir(root: Path, task_id: str) -> Path:
    if not TASK_RE.fullmatch(task_id):
        raise BrokerError("INVALID_TASK_ID", "invalid task id")
    base = (root / "challenges" / "current").resolve()
    task = (base / task_id).resolve()
    if task.parent != base or not task.is_dir():
        raise BrokerError("TASK_NOT_FOUND", f"task not found: {task_id}", HTTPStatus.NOT_FOUND)
    return task


class DockerBroker:
    def __init__(self, root: Path, images: dict[str, str]):
        self.root = root.resolve()
        self.images = images
        self.docker = shutil.which("docker") or r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"
        self.log_path = self.root / "logs" / "docker-broker.jsonl"
        self.log_lock = threading.Lock()

    def log(self, event: dict[str, Any]) -> None:
        event = {"timestamp": utc_timestamp(), **event}
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_lock:
            with self.log_path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")

    def run(
        self,
        command: list[str],
        *,
        timeout: int,
        cwd: Path | None = None,
        max_output: int = 1024 * 1024,
    ) -> dict[str, Any]:
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
            stdout = completed.stdout[:max_output]
            stderr = completed.stderr[:max_output]
            result = {
                "ok": completed.returncode == 0,
                "exit_code": completed.returncode,
                "duration_ms": int((time.monotonic() - started) * 1000),
                "stdout": stdout.decode("utf-8", "replace"),
                "stderr": stderr.decode("utf-8", "replace"),
                "truncated": len(completed.stdout) > len(stdout) or len(completed.stderr) > len(stderr),
            }
            self.log({"type": "command", "command": command, "result": result})
            return result
        except subprocess.TimeoutExpired as exc:
            result = {
                "ok": False,
                "exit_code": None,
                "duration_ms": int((time.monotonic() - started) * 1000),
                "stdout": (exc.stdout or b"").decode("utf-8", "replace") if exc.stdout else "",
                "stderr": (exc.stderr or b"").decode("utf-8", "replace") if exc.stderr else "",
                "truncated": False,
                "error": f"timeout after {timeout} seconds",
            }
            self.log({"type": "timeout", "command": command, "result": result})
            return result

    def health(self) -> dict[str, Any]:
        result = self.run([self.docker, "info", "--format", "{{json .}}"], timeout=10)
        parsed: dict[str, Any] = {}
        if result["ok"]:
            try:
                info = json.loads(result["stdout"])
                parsed = {
                    "ostype": info.get("OSType"),
                    "architecture": info.get("Architecture"),
                    "server_version": info.get("ServerVersion"),
                    "root": info.get("DockerRootDir"),
                    "images": info.get("Images"),
                    "containers": info.get("Containers"),
                }
            except json.JSONDecodeError:
                parsed = {}
        return {
            "ok": result["ok"],
            "docker": self.docker,
            "info": parsed,
            "error": result.get("error") or (None if result["ok"] else result["stderr"]),
        }

    def _image(self, profile: str) -> str:
        if profile not in self.images:
            raise BrokerError("PROFILE_NOT_ALLOWED", f"profile is not allowed: {profile}")
        return self.images[profile]

    def create(self, task_id: str, profile: str) -> dict[str, Any]:
        if profile not in SANDBOX_PROFILES:
            raise BrokerError("PROFILE_NOT_ALLOWED", f"sandbox profile is not allowed: {profile}")
        image = self._image(profile)
        task = resolve_task_dir(self.root, task_id)
        work = task / "work"
        work.mkdir(exist_ok=True)
        name = f"ctf-agent-{task_id[-6:]}-{secrets.token_hex(3)}"
        mounts = [
            ("input", "input", True),
            ("artifacts", "artifacts", False),
            ("exploit", "exploit", False),
            ("work", "work", False),
        ]
        command = [
            self.docker,
            "run",
            "-d",
            "--name",
            name,
            "--label",
            "ctf-agent=true",
            "--label",
            f"ctf-task={task_id}",
            "--label",
            f"ctf-profile={profile}",
            "--network",
            "none",
            "--cpus",
            "2",
            "--memory",
            "4g",
            "--pids-limit",
            "512",
            "--shm-size",
            "512m",
            "--security-opt",
            "no-new-privileges",
            "--cap-drop",
            "ALL",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,exec,nosuid,nodev,size=512m",
            "--env",
            "CTF_TOOLS=/opt/ctf-tools",
            "--env",
            "PATH=/opt/ctf-tools/bin:/opt/ctf-venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ]
        for source_name, target_name, readonly in mounts:
            source = (task / source_name).resolve()
            mount = f"type=bind,source={source},target=/challenge/{target_name}"
            if readonly:
                mount += ",readonly"
            command.extend(["--mount", mount])
        tool_runtime = (self.root / "tool-runtime").resolve()
        if tool_runtime.is_dir():
            command.extend(
                [
                    "--mount",
                    f"type=bind,source={tool_runtime},target=/opt/ctf-tools,readonly",
                ]
            )
        command.extend([image, "sleep", "infinity"])
        result = self.run(command, timeout=120)
        if not result["ok"]:
            raise BrokerError(
                "CONTAINER_CREATE_FAILED",
                result["stderr"] or result.get("error") or "docker run failed",
                500,
            )
        return {
            "container_id": result["stdout"].strip().splitlines()[-1],
            "name": name,
            "task_id": task_id,
            "profile": profile,
            "image": image,
            "network": "none",
        }

    def _verify_container(self, task_id: str, container_id: str) -> None:
        if not CONTAINER_RE.fullmatch(container_id):
            raise BrokerError("INVALID_CONTAINER", "invalid container id")
        result = self.run(
            [
                self.docker,
                "inspect",
                "-f",
                '{{ index .Config.Labels "ctf-task" }}',
                container_id,
            ],
            timeout=15,
        )
        if not result["ok"]:
            raise BrokerError("CONTAINER_NOT_FOUND", result["stderr"], 404)
        if result["stdout"].strip() != task_id:
            raise BrokerError("CONTAINER_TASK_MISMATCH", "container does not belong to task", 403)

    def execute(
        self,
        task_id: str,
        container_id: str,
        command: str,
        timeout_seconds: int,
    ) -> dict[str, Any]:
        self._verify_container(task_id, container_id)
        if not command.strip() or len(command) > MAX_COMMAND_CHARS:
            raise BrokerError("INVALID_COMMAND", "command is empty or too large")
        timeout_seconds = max(1, min(int(timeout_seconds), 300))
        wrapped = (
            f"cd /challenge/work && timeout --signal=KILL --kill-after=5 "
            f"{timeout_seconds} bash -lc {shlex.quote(command)}"
        )
        result = self.run(
            [self.docker, "exec", "-i", container_id, "bash", "-lc", wrapped],
            timeout=timeout_seconds + 10,
            max_output=1024 * 1024,
        )
        return {
            "container_id": container_id,
            "task_id": task_id,
            "command": command,
            **result,
        }

    def stop(self, task_id: str, container_id: str) -> dict[str, Any]:
        self._verify_container(task_id, container_id)
        result = self.run([self.docker, "rm", "-f", container_id], timeout=30)
        if not result["ok"]:
            raise BrokerError("CONTAINER_STOP_FAILED", result["stderr"], 500)
        return {"container_id": container_id, "task_id": task_id, "stopped": True}

    def build(self, profile: str, timeout_seconds: int = 1800) -> dict[str, Any]:
        image = self._image(profile)
        directory = (
            self.root / "docker" / "labs" / profile
            if profile == "juice-shop"
            else self.root / "docker" / profile
        )
        dockerfile = directory / "Dockerfile"
        if not dockerfile.is_file():
            raise BrokerError("DOCKERFILE_NOT_FOUND", f"missing {dockerfile}", 404)
        result = self.run(
            [self.docker, "build", "-t", image, "-f", str(dockerfile), str(directory)],
            timeout=max(60, min(int(timeout_seconds), 3600)),
            max_output=4 * 1024 * 1024,
        )
        if not result["ok"]:
            raise BrokerError("IMAGE_BUILD_FAILED", result["stderr"] or "docker build failed", 500)
        return {"image": image, "profile": profile, "build": result}

    def lab_start(self, lab: str, host_port: int = 3000) -> dict[str, Any]:
        if lab not in LABS:
            raise BrokerError("LAB_NOT_ALLOWED", f"lab is not allowed: {lab}")
        if host_port < 1024 or host_port > 65535:
            raise BrokerError("INVALID_PORT", "lab host port must be between 1024 and 65535")
        config = LABS[lab]
        image = self._image(str(config["profile"]))
        name = str(config["container_name"])
        inspect = self.run(
            [self.docker, "inspect", "-f", "{{.State.Running}}", name],
            timeout=15,
        )
        if inspect["ok"]:
            if inspect["stdout"].strip().lower() != "true":
                started = self.run([self.docker, "start", name], timeout=60)
                if not started["ok"]:
                    raise BrokerError("LAB_START_FAILED", started["stderr"], 500)
            return {
                "lab": lab,
                "container_name": name,
                "url": f"http://127.0.0.1:{host_port}",
                "image": image,
                "reused": True,
            }
        command = [
            self.docker,
            "run",
            "-d",
            "--name",
            name,
            "--label",
            "ctf-agent-lab=true",
            "--label",
            f"ctf-lab={lab}",
            "--publish",
            f"127.0.0.1:{host_port}:{config['container_port']}",
            "--cpus",
            "1",
            "--memory",
            "1g",
            "--pids-limit",
            "256",
            "--security-opt",
            "no-new-privileges",
            "--cap-drop",
            "ALL",
            "--mount",
            f"type=volume,source=ctf-agent-{lab}-data,target=/juice-shop/data",
            image,
        ]
        result = self.run(command, timeout=120)
        if not result["ok"]:
            raise BrokerError("LAB_START_FAILED", result["stderr"] or "docker run failed", 500)
        return {
            "lab": lab,
            "container_id": result["stdout"].strip().splitlines()[-1],
            "container_name": name,
            "url": f"http://127.0.0.1:{host_port}",
            "image": image,
            "reused": False,
        }

    def lab_stop(self, lab: str) -> dict[str, Any]:
        if lab not in LABS:
            raise BrokerError("LAB_NOT_ALLOWED", f"lab is not allowed: {lab}")
        name = str(LABS[lab]["container_name"])
        result = self.run([self.docker, "stop", name], timeout=60)
        if not result["ok"] and "No such container" not in result["stderr"]:
            raise BrokerError("LAB_STOP_FAILED", result["stderr"], 500)
        return {"lab": lab, "container_name": name, "stopped": result["ok"]}

    def lab_status(self, lab: str) -> dict[str, Any]:
        if lab not in LABS:
            raise BrokerError("LAB_NOT_ALLOWED", f"lab is not allowed: {lab}")
        name = str(LABS[lab]["container_name"])
        result = self.run(
            [self.docker, "inspect", "-f", "{{json .State}}", name],
            timeout=15,
        )
        if not result["ok"]:
            return {"lab": lab, "container_name": name, "exists": False}
        return {
            "lab": lab,
            "container_name": name,
            "exists": True,
            "state": json.loads(result["stdout"]),
        }


class BrokerServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], broker: DockerBroker, token: str):
        super().__init__(address, Handler)
        self.broker = broker
        self.token = token


class Handler(BaseHTTPRequestHandler):
    server: BrokerServer

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        return secrets.compare_digest(header, f"Bearer {self.server.token}")

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_BODY_BYTES:
            raise BrokerError("INVALID_BODY", "request body is empty or too large")
        payload = json.loads(self.rfile.read(length))
        if not isinstance(payload, dict):
            raise BrokerError("INVALID_BODY", "JSON body must be an object")
        return payload

    def do_GET(self) -> None:
        if not self._authorized():
            self._send(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "unauthorized"})
            return
        if self.path == "/health":
            self._send(HTTPStatus.OK, {"ok": True, **self.server.broker.health()})
            return
        self._send(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        if not self._authorized():
            self._send(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "unauthorized"})
            return
        try:
            payload = self._body()
            if self.path == "/v1/create":
                result = self.server.broker.create(
                    str(payload["task_id"]),
                    str(payload["profile"]),
                )
            elif self.path == "/v1/exec":
                result = self.server.broker.execute(
                    str(payload["task_id"]),
                    str(payload["container_id"]),
                    str(payload["command"]),
                    int(payload.get("timeout_seconds", 60)),
                )
            elif self.path == "/v1/stop":
                result = self.server.broker.stop(
                    str(payload["task_id"]),
                    str(payload["container_id"]),
                )
            elif self.path == "/v1/build":
                result = self.server.broker.build(
                    str(payload["profile"]),
                    int(payload.get("timeout_seconds", 1800)),
                )
            elif self.path == "/v1/lab/start":
                result = self.server.broker.lab_start(
                    str(payload["lab"]),
                    int(payload.get("host_port", 3000)),
                )
            elif self.path == "/v1/lab/stop":
                result = self.server.broker.lab_stop(str(payload["lab"]))
            elif self.path == "/v1/lab/status":
                result = self.server.broker.lab_status(str(payload["lab"]))
            else:
                raise BrokerError("NOT_FOUND", "not found", HTTPStatus.NOT_FOUND)
            self._send(HTTPStatus.OK, {"ok": True, "data": result})
        except BrokerError as exc:
            self._send(exc.status, {"ok": False, "error": exc.code, "message": str(exc)})
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            self._send(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "INVALID_REQUEST", "message": str(exc)})
        except Exception as exc:
            self._send(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": "INTERNAL_ERROR", "message": str(exc)})


def parse_images(value: str | None) -> dict[str, str]:
    if not value:
        return dict(PROFILE_DEFAULT_IMAGES)
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError("image map must be a JSON object")
    return {str(key): str(item) for key, item in parsed.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Restricted local Docker broker for CTF Agent")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[2]))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--token-file")
    parser.add_argument("--images", default=os.environ.get("CTF_BROKER_IMAGES"))
    args = parser.parse_args(argv)
    if args.host != "127.0.0.1":
        parser.error("broker may only bind to 127.0.0.1")
    root = Path(args.root).resolve()
    token_path = Path(args.token_file) if args.token_file else root / "config" / "docker-broker-token"
    token = ensure_token(token_path)
    broker = DockerBroker(root, parse_images(args.images))
    server = BrokerServer((args.host, args.port), broker, token)
    print(f"Docker broker listening on http://{args.host}:{args.port}", file=sys.stderr)
    print(f"Token file: {token_path}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
