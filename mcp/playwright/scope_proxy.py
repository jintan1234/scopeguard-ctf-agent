from __future__ import annotations

import argparse
import json
import select
import socket
import socketserver
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


MAX_HEADER_BYTES = 64 * 1024
BLOCKED_HOSTS = {"metadata.google.internal", "metadata", "instance-data"}


def _normalise_host(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    return value


def _load_scope(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def destination_allowed(
    scope: dict[str, Any] | None,
    host: str,
    port: int,
    scheme: str,
) -> tuple[bool, str]:
    if not scope or not scope.get("authorized"):
        return False, "no active authorized scope"
    host = _normalise_host(host)
    if host in BLOCKED_HOSTS:
        return False, "blocked metadata host"
    if scheme not in set(scope.get("allowed_schemes", [])):
        return False, f"scheme blocked: {scheme}"
    if host not in {_normalise_host(value) for value in scope.get("allowed_hosts", [])}:
        return False, f"host blocked: {host}"
    if int(port) not in {int(value) for value in scope.get("allowed_ports", [])}:
        return False, f"port blocked: {port}"
    return True, "allowed"


class ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], scope_file: Path, log_file: Path):
        super().__init__(address, ProxyHandler)
        self.scope_file = scope_file
        self.log_file = log_file
        self.log_lock = threading.Lock()

    def log(self, event: dict[str, Any]) -> None:
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        with self.log_lock:
            with self.log_file.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(
                    json.dumps(
                        {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **event},
                        ensure_ascii=False,
                    )
                    + "\n"
                )


class ProxyHandler(socketserver.StreamRequestHandler):
    server: ProxyServer

    def _deny(self, reason: str) -> None:
        self.server.log({"type": "blocked", "reason": reason})
        body = f"CTF scope proxy blocked request: {reason}\n".encode()
        self.wfile.write(
            b"HTTP/1.1 403 Forbidden\r\n"
            b"Content-Type: text/plain\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n\r\n"
            + body
        )

    def handle(self) -> None:
        raw_head = b""
        while b"\r\n\r\n" not in raw_head and len(raw_head) <= MAX_HEADER_BYTES:
            chunk = self.rfile.readline()
            if not chunk:
                return
            raw_head += chunk
        head_text = raw_head.decode("iso-8859-1")
        lines = head_text.split("\r\n")
        try:
            method, target, version = lines[0].split(" ", 2)
        except ValueError:
            self._deny("invalid request line")
            return
        scope = _load_scope(self.server.scope_file)
        if method.upper() == "CONNECT":
            parsed = urlsplit("//" + target)
            host = parsed.hostname or ""
            port = parsed.port or 443
            allowed, reason = destination_allowed(scope, host, port, "https")
            if not allowed:
                self._deny(reason)
                return
            try:
                upstream = socket.create_connection((host, port), timeout=15)
            except OSError as exc:
                self._deny(f"upstream connect failed: {exc}")
                return
            self.server.log(
                {"type": "connect", "host": host, "port": port, "scope_task": (scope or {}).get("task_id")}
            )
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.wfile.flush()
            self._relay(upstream)
            return

        parsed_target = urlsplit(target)
        if parsed_target.scheme:
            scheme = parsed_target.scheme
            host = parsed_target.hostname or ""
            port = parsed_target.port or (443 if scheme == "https" else 80)
            path = parsed_target.path or "/"
            if parsed_target.query:
                path += "?" + parsed_target.query
        else:
            host_header = next(
                (
                    line.split(":", 1)[1].strip()
                    for line in lines[1:]
                    if line.lower().startswith("host:")
                ),
                "",
            )
            parsed_host = urlsplit("//" + host_header)
            host = parsed_host.hostname or ""
            port = parsed_host.port or 80
            scheme = "http"
            path = target
        allowed, reason = destination_allowed(scope, host, port, scheme)
        if not allowed:
            self._deny(reason)
            return
        if scheme == "https":
            self._deny("HTTPS must use CONNECT")
            return
        try:
            upstream = socket.create_connection((host, port), timeout=15)
        except OSError as exc:
            self._deny(f"upstream connect failed: {exc}")
            return
        self.server.log(
            {"type": "http", "method": method, "host": host, "port": port, "path": path[:2048]}
        )
        headers = []
        for line in lines[1:]:
            if not line:
                continue
            lower = line.lower()
            if lower.startswith(("proxy-connection:", "connection:", "keep-alive:")):
                continue
            headers.append(line)
        upstream.sendall(
            f"{method} {path} {version}\r\n".encode("iso-8859-1")
            + ("\r\n".join(headers) + "\r\n\r\n").encode("iso-8859-1")
        )
        self._relay(upstream)

    def _relay(self, upstream: socket.socket) -> None:
        sockets = [self.connection, upstream]
        try:
            while True:
                readable, _, _ = select.select(sockets, [], [], 30)
                if not readable:
                    continue
                for current in readable:
                    data = current.recv(64 * 1024)
                    if not data:
                        return
                    destination = upstream if current is self.connection else self.connection
                    destination.sendall(data)
        except OSError:
            return
        finally:
            upstream.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--scope-file", required=True)
    parser.add_argument("--log-file", required=True)
    args = parser.parse_args()
    if args.host != "127.0.0.1":
        parser.error("scope proxy must bind to 127.0.0.1")
    server = ProxyServer(
        (args.host, args.port),
        Path(args.scope_file).resolve(),
        Path(args.log_file).resolve(),
    )
    print(f"Playwright scope proxy listening on 127.0.0.1:{args.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
