from __future__ import annotations

import json
import sys
import traceback
from typing import Any, BinaryIO

from .mcp_tools import ToolRegistry, mcp_tool_result


PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "ctf-control"
SERVER_VERSION = "0.1.0"


def _read_message(stream: BinaryIO) -> tuple[dict[str, Any] | None, str | None]:
    first = stream.readline()
    if not first:
        return None, None
    stripped = first.strip()
    if stripped.lower().startswith(b"content-length:"):
        length = int(stripped.split(b":", 1)[1].strip())
        while True:
            header = stream.readline()
            if header in (b"\r\n", b"\n", b""):
                break
        payload = stream.read(length)
        return json.loads(payload.decode("utf-8")), "content-length"
    if not stripped:
        return {}, "line"
    return json.loads(stripped.decode("utf-8")), "line"


def _write_message(message: dict[str, Any], framing: str | None) -> None:
    payload = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if framing == "content-length":
        sys.stdout.buffer.write(f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii"))
        sys.stdout.buffer.write(payload)
    else:
        sys.stdout.buffer.write(payload + b"\n")
    sys.stdout.buffer.flush()


def main() -> int:
    registry = ToolRegistry()
    framing: str | None = None
    while True:
        try:
            message, observed_framing = _read_message(sys.stdin.buffer)
            if message is None:
                return 0
            framing = observed_framing or framing or "line"
            if not message:
                continue
            method = message.get("method")
            message_id = message.get("id")
            if message_id is None and str(method).startswith("notifications/"):
                continue
            if method == "initialize":
                result = {
                    "protocolVersion": message.get("params", {}).get(
                        "protocolVersion", PROTOCOL_VERSION
                    ),
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                }
                _write_message({"jsonrpc": "2.0", "id": message_id, "result": result}, framing)
            elif method == "ping":
                _write_message({"jsonrpc": "2.0", "id": message_id, "result": {}}, framing)
            elif method == "tools/list":
                _write_message(
                    {
                        "jsonrpc": "2.0",
                        "id": message_id,
                        "result": {"tools": registry.definitions()},
                    },
                    framing,
                )
            elif method == "tools/call":
                params = message.get("params", {})
                name = params.get("name", "")
                arguments = params.get("arguments") or {}
                result = registry.call(name, arguments)
                _write_message(
                    {
                        "jsonrpc": "2.0",
                        "id": message_id,
                        "result": mcp_tool_result(result),
                    },
                    framing,
                )
            elif method in {"notifications/initialized", "notifications/cancelled"}:
                continue
            else:
                _write_message(
                    {
                        "jsonrpc": "2.0",
                        "id": message_id,
                        "error": {"code": -32601, "message": f"Method not found: {method}"},
                    },
                    framing,
                )
        except json.JSONDecodeError as exc:
            print(f"ctf-control: invalid JSON-RPC message: {exc}", file=sys.stderr)
        except Exception as exc:
            print(f"ctf-control: server error: {exc}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            try:
                _write_message(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32603, "message": "Internal error"},
                    },
                    framing,
                )
            except Exception:
                return 1


if __name__ == "__main__":
    raise SystemExit(main())
