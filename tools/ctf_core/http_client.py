from __future__ import annotations

import http.client
import ssl
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from .evidence import EvidenceLedger
from .flagops import discover_candidates
from .models import ToolError, envelope
from .scope import ScopePolicy
from .task import TaskManager
from .util import redact_url


ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
DEFAULT_HEADERS = {
    "User-Agent": "LocalCTFAgent/0.1 (authorized-lab)",
    "Accept": "*/*",
}


def _request_once(
    url: str,
    *,
    method: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout: float,
    max_bytes: int,
    insecure: bool,
) -> tuple[int, str, dict[str, str], bytes, str | None, bytes]:
    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        raise ValueError("URL has no hostname")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    if parts.scheme == "https":
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(
            host, port, timeout=timeout, context=context
        )
    else:
        connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        raw = response.read(max_bytes + 1)
        truncated = len(raw) > max_bytes
        payload = raw[:max_bytes]
        return (
            response.status,
            response.reason,
            response_headers,
            payload,
            response_headers.get("location"),
            b"\r\n".join(
                [f"HTTP/1.1 {response.status} {response.reason}".encode()]
                + [f"{key}: {value}".encode() for key, value in response.getheaders()]
                + [b"", payload]
            ),
        )
    finally:
        connection.close()


def perform_request(
    task_manager: TaskManager,
    task_id: str,
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | bytes | None = None,
    timeout_seconds: float = 15.0,
    max_response_bytes: int = 2 * 1024 * 1024,
    follow_redirects: bool = False,
    insecure_tls: bool = False,
) -> dict[str, Any]:
    started = time.monotonic()
    start_wall = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    ledger: EvidenceLedger | None = None
    try:
        method = method.upper()
        if method not in ALLOWED_METHODS:
            raise ValueError(f"method is not allowed: {method}")
        task_dir = task_manager.get_dir(task_id)
        ledger = EvidenceLedger(task_dir)
        policy = ScopePolicy.from_task(task_dir)
        current_url = url
        if len(current_url) > 8192:
            raise ValueError("URL is too long")
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body
        request_headers = {**DEFAULT_HEADERS, **(headers or {})}
        hops: list[dict[str, Any]] = []
        final_status = 0
        final_reason = ""
        final_headers: dict[str, str] = {}
        final_body = b""
        raw_response = b""
        for redirect_index in range(6):
            checked = policy.validate_url(current_url, redirect=redirect_index > 0)
            status, reason, response_headers, payload, location, raw = _request_once(
                current_url,
                method=method,
                headers=request_headers,
                body=body_bytes,
                timeout=timeout_seconds,
                max_bytes=max_response_bytes,
                insecure=insecure_tls,
            )
            hops.append(
                {
                    "url": redact_url(current_url),
                    "status": status,
                    "resolved_ips": checked["resolved_ips"],
                    "location": redact_url(urljoin(current_url, location)) if location else None,
                }
            )
            final_status = status
            final_reason = reason
            final_headers = response_headers
            final_body = payload
            raw_response = raw
            if (
                follow_redirects
                and status in {301, 302, 303, 307, 308}
                and location
                and redirect_index < 5
            ):
                next_url = urljoin(current_url, location)
                if status == 303 or (status in {301, 302} and method == "POST"):
                    method = "GET"
                    body_bytes = None
                current_url = next_url
                continue
            break
        else:
            raise ValueError("too many redirects")
        artifact_dir = task_dir / "artifacts"
        artifact_dir.mkdir(exist_ok=True)
        artifact_path = artifact_dir / f"http-{int(time.time() * 1000)}-response.bin"
        artifact_path.write_bytes(raw_response[: max_response_bytes + 65536])
        artifact = ledger.artifact(artifact_path, kind="http-response", source_tool="ctf_http_request")
        text_preview: str | None
        try:
            text_preview = final_body.decode("utf-8")
        except UnicodeDecodeError:
            text_preview = None
        flag_candidates = discover_candidates(text_preview) if text_preview else []
        ledger.event(
            "http_request",
            request_url=redact_url(url),
            final_url=redact_url(current_url),
            method=method,
            status=final_status,
            hops=hops,
        )
        ledger.command(
            ["internal:http", method, redact_url(url)],
            cwd=task_dir.as_posix(),
            exit_code=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            stdout_summary=f"status={final_status} bytes={len(final_body)}",
        )
        return envelope(
            "ctf_http_request",
            ok=True,
            task_id=task_id,
            started_at=start_wall,
            duration_ms=int((time.monotonic() - started) * 1000),
            truncated=len(raw_response) > max_response_bytes,
            data={
                "requested_url": redact_url(url),
                "final_url": redact_url(current_url),
                "status": final_status,
                "reason": final_reason,
                "headers": final_headers,
                "text": text_preview,
                "body_hex": None if text_preview is not None else final_body[:4096].hex(),
                "body_bytes": len(final_body),
                "hops": hops,
                "flag_candidates": flag_candidates[:100],
            },
            artifacts=[artifact],
        )
    except Exception as exc:
        if ledger is not None:
            ledger.event("tool_error", tool="ctf_http_request", error=str(exc), url=redact_url(url))
        return envelope(
            "ctf_http_request",
            ok=False,
            task_id=task_id,
            started_at=start_wall,
            duration_ms=int((time.monotonic() - started) * 1000),
            exit_code=1,
            error=ToolError("HTTP_REQUEST_FAILED", str(exc)),
        )
