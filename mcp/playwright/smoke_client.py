from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[2]
SERVER = Path(__file__).resolve().with_name(
    "server.cmd" if os.name == "nt" else "server.sh"
)
sys.path.insert(0, str(PROJECT / "tools"))

from ctf_core.task import TaskManager  # noqa: E402


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/api/status":
            body = b'{"ok":true,"marker":"MCP_NETWORK_OBSERVED"}'
            content_type = "application/json"
        else:
            body = (
                b"<!doctype html><html><head><title>CTF MCP Smoke</title></head>"
                b"<body><h1>Local MCP Smoke</h1>"
                b"<button id='probe' onclick=\"document.getElementById('result').textContent='CLICK_OK'\">Probe API</button>"
                b"<div id='result'>not-clicked</div>"
                b"<script>fetch('/api/status').catch(()=>{});</script>"
                b"</body></html>"
            )
            content_type = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class McpClient:
    def __init__(self, state_root: Path, proxy_port: int) -> None:
        env = os.environ.copy()
        env["CTF_AGENT_ROOT"] = str(state_root)
        env["CTF_PLAYWRIGHT_PROXY_PORT"] = str(proxy_port)
        env["CTF_PLAYWRIGHT_OUTPUT_DIR"] = str(
            state_root / "challenges" / "current" / "browser-output"
        )
        command = [str(SERVER)] if os.name == "nt" else ["sh", str(SERVER)]
        self.proc = subprocess.Popen(
            command,
            cwd=PROJECT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=env,
        )
        self.next_id = 1
        self.stderr_lines: list[str] = []
        self.stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self.stderr_thread.start()

    def _drain_stderr(self) -> None:
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            self.stderr_lines.append(line.rstrip())

    def send(self, method: str, params: dict | None = None) -> dict:
        message = {
            "jsonrpc": "2.0",
            "id": self.next_id,
            "method": method,
            "params": params or {},
        }
        message_id = self.next_id
        self.next_id += 1
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()
        while True:
            assert self.proc.stdout is not None
            line = self.proc.stdout.readline()
            if not line:
                stderr = self.proc.stderr.read() if self.proc.stderr else ""
                raise RuntimeError(f"MCP server exited before response: {stderr}")
            response = json.loads(line)
            if response.get("id") == message_id:
                if "error" in response:
                    raise RuntimeError(response["error"])
                return response["result"]

    def notify(self, method: str, params: dict | None = None) -> None:
        assert self.proc.stdin is not None
        message = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        self.proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()

    def call(self, name: str, arguments: dict) -> dict:
        return self.send("tools/call", {"name": name, "arguments": arguments})

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.stderr_thread.join(timeout=2)


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state_temp = tempfile.TemporaryDirectory()
    state_root = Path(state_temp.name)
    tasks = TaskManager(state_root)
    created = tasks.create(
        f"http://127.0.0.1:{server.server_port}/",
        "Playwright MCP smoke test.",
        authorized=True,
    )
    task_id = created["task"]["task_id"]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        proxy_port = int(probe.getsockname()[1])
    client = McpClient(state_root, proxy_port)
    try:
        initialized = client.send(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "ctf-playwright-smoke", "version": "0.1.0"},
            },
        )
        client.notify("notifications/initialized")
        tools = client.send("tools/list")
        url = f"http://127.0.0.1:{server.server_port}/"
        navigated = client.call("browser_navigate", {"url": url})
        snapshot = client.call("browser_snapshot", {"depth": 8})
        clicked = client.call(
            "browser_click",
            {"element": "Probe API button", "target": "e3"},
        )
        clicked_snapshot = client.call("browser_snapshot", {"depth": 8})
        network = client.call(
            "browser_network_requests",
            {"filter": "/api/status", "all": True},
        )
        blocked = client.call("browser_navigate", {"url": "http://example.com/"})
        snapshot_text = "".join(
            item.get("text", "")
            for item in snapshot.get("content", [])
            if item.get("type") == "text"
        )
        network_text = "".join(
            item.get("text", "")
            for item in network.get("content", [])
            if item.get("type") == "text"
        )
        navigate_text = "".join(
            item.get("text", "")
            for item in navigated.get("content", [])
            if item.get("type") == "text"
        )
        clicked_snapshot_text = "".join(
            item.get("text", "")
            for item in clicked_snapshot.get("content", [])
            if item.get("type") == "text"
        )
        blocked_text = "".join(
            item.get("text", "")
            for item in blocked.get("content", [])
            if item.get("type") == "text"
        )
        state = tasks.get(task_id)["state"]
        event_text = (state_root / "challenges" / "current" / task_id / "evidence" / "events.jsonl").read_text(
            encoding="utf-8"
        )
        browser_events = sum(1 for line in event_text.splitlines() if '"browser_tool_call"' in line)
        browser_artifact_events = sum(
            1
            for line in event_text.splitlines()
            if '"type": "artifact"' in line and '"source_tool": "playwright-mcp"' in line
        )
        browser_tool_calls = int(state.get("tool_calls", 0))
        result = {
            "ok": (
                not navigated.get("isError")
                and not snapshot.get("isError")
                and "Local MCP Smoke" in snapshot_text
                and not clicked.get("isError")
                and "CLICK_OK" in clicked_snapshot_text
                and "/api/status" in network_text
                and ("403" in blocked_text or "blocked" in blocked_text.lower())
                and browser_tool_calls >= 6
                and browser_events >= 6
                and browser_artifact_events >= 1
            ),
            "server": initialized.get("serverInfo"),
            "protocol": initialized.get("protocolVersion"),
            "tool_count": len(tools.get("tools", [])),
            "navigate_error": navigated.get("isError"),
            "snapshot_error": snapshot.get("isError"),
            "network_error": network.get("isError"),
            "snapshot_contains_heading": "Local MCP Smoke" in snapshot_text,
            "click_error": clicked.get("isError"),
            "click_updated_dom": "CLICK_OK" in clicked_snapshot_text,
            "network_contains_api": "/api/status" in network_text,
            "out_of_scope_blocked": (
                "403" in blocked_text or "blocked" in blocked_text.lower()
            ),
            "browser_tool_calls": browser_tool_calls,
            "browser_evidence_events": browser_events,
            "browser_artifact_events": browser_artifact_events,
            "blocked_text": blocked_text[:1000],
            "navigate_text": navigate_text[:2000],
            "snapshot_text": snapshot_text[:2000],
            "network_text": network_text[:2000],
            "clicked_snapshot_text": clicked_snapshot_text[:2000],
            "server_stderr": client.stderr_lines[-30:],
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["ok"] else 1
    finally:
        client.close()
        state_temp.cleanup()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
