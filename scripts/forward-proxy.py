#!/usr/bin/env python3
"""Small allowlisted HTTP CONNECT proxy for recovering WSL package access."""

from __future__ import annotations

import argparse
import json
import select
import socket
import socketserver
import threading
from datetime import UTC, datetime
from pathlib import Path


ALLOWED_HOSTS = {
    "api.github.com",
    "archive.ubuntu.com",
    "codeload.github.com",
    "files.pythonhosted.org",
    "github.com",
    "index.rubygems.org",
    "objects.githubusercontent.com",
    "packages.microsoft.com",
    "pypi.org",
    "raw.githubusercontent.com",
    "rubygems.org",
    "security.ubuntu.com",
}
ALLOWED_PORTS = {80, 443}


def host_allowed(host: str) -> bool:
    host = host.rstrip(".").lower()
    return any(host == allowed or host.endswith(f".{allowed}") for allowed in ALLOWED_HOSTS)


def log_event(path: Path, event: dict[str, object]) -> None:
    event["time"] = datetime.now(UTC).isoformat()
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=True) + "\n")


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client = self.request
        client.settimeout(15)
        try:
            request = self._read_headers(client)
            if not request:
                return
            method, target, _ = request.split("\r\n", 1)[0].split(" ", 2)
            if method.upper() != "CONNECT":
                self._send_error(client, 405, "Only CONNECT is supported")
                return

            host, port_text = self._split_authority(target)
            port = int(port_text)
            if port not in ALLOWED_PORTS or not host_allowed(host):
                log_event(self.server.log_path, {"result": "denied", "host": host, "port": port})
                self._send_error(client, 403, "Destination is not allowlisted")
                return

            upstream = socket.create_connection((host, port), timeout=15)
            upstream.settimeout(None)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            log_event(self.server.log_path, {"result": "connected", "host": host, "port": port})
            self._relay(client, upstream)
        except (OSError, ValueError) as exc:
            log_event(self.server.log_path, {"result": "error", "error": type(exc).__name__})
            self._send_error(client, 502, "Upstream connection failed")
        finally:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    @staticmethod
    def _read_headers(client: socket.socket) -> str:
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = client.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 64 * 1024:
                raise ValueError("Request headers are too large")
        return data.decode("latin-1", errors="replace")

    @staticmethod
    def _split_authority(authority: str) -> tuple[str, str]:
        if authority.startswith("["):
            end = authority.index("]")
            return authority[1:end], authority[end + 2 :]
        host, port = authority.rsplit(":", 1)
        return host, port

    @staticmethod
    def _send_error(client: socket.socket, status: int, message: str) -> None:
        body = message.encode("utf-8")
        client.sendall(
            f"HTTP/1.1 {status} Error\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n".encode("ascii")
            + body
        )

    @staticmethod
    def _relay(client: socket.socket, upstream: socket.socket) -> None:
        sockets = [client, upstream]
        try:
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, 60)
                if exceptional or not readable:
                    return
                for source in readable:
                    data = source.recv(64 * 1024)
                    if not data:
                        return
                    destination = upstream if source is client else client
                    destination.sendall(data)
        finally:
            upstream.close()


class ThreadingProxy(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], log_path: Path):
        self.log_path = log_path
        super().__init__(address, ProxyHandler)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", default=3128, type=int)
    parser.add_argument("--log", required=True, type=Path)
    args = parser.parse_args()
    args.log.parent.mkdir(parents=True, exist_ok=True)
    with ThreadingProxy((args.host, args.port), args.log) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
