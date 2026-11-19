from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import socket
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator


class PolicyError(ValueError):
    """Raised when an operation exceeds a configured safety boundary."""


def project_root() -> Path:
    configured = os.environ.get("CTF_AGENT_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[2]


def resolve_within(root: Path, candidate: str | Path, *, must_exist: bool = False) -> Path:
    root = root.resolve()
    path = Path(candidate)
    if not path.is_absolute():
        path = root / path
    resolved = path.resolve(strict=must_exist)
    if resolved != root and root not in resolved.parents:
        raise PolicyError(f"path escapes allowed root: {candidate}")
    return resolved


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temp_name)


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


@contextlib.contextmanager
def exclusive_lock(lock_path: Path, timeout_seconds: float = 10.0) -> Iterator[None]:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, f"{os.getpid()} {time.time()}\n".encode("ascii"))
            os.close(fd)
            break
        except FileExistsError:
            try:
                age = time.time() - lock_path.stat().st_mtime
                if age > 30:
                    lock_path.unlink(missing_ok=True)
                    continue
            except FileNotFoundError:
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError(f"timed out waiting for lock: {lock_path}")
            time.sleep(0.05)
    try:
        yield
    finally:
        with contextlib.suppress(FileNotFoundError):
            lock_path.unlink()


def append_jsonl(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_suffix(path.suffix + ".lock")
    with exclusive_lock(lock):
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(value, ensure_ascii=False, default=str))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_copy_file(source: Path, destination_dir: Path, max_bytes: int) -> Path:
    source = source.expanduser().resolve(strict=True)
    if not source.is_file() or source.is_symlink():
        raise PolicyError(f"attachment must be a regular file: {source}")
    if source.stat().st_size > max_bytes:
        raise PolicyError(f"attachment exceeds limit of {max_bytes} bytes: {source}")
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / source.name
    if destination.exists():
        stem = destination.stem
        suffix = destination.suffix
        counter = 1
        while destination.exists():
            destination = destination_dir / f"{stem}-{counter}{suffix}"
            counter += 1
    shutil.copy2(source, destination)
    return destination


def redact_url(url: str) -> str:
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    parts = urlsplit(url)
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    userinfo = ""
    sensitive = {"token", "key", "secret", "password", "passwd", "jwt", "session", "auth"}
    query = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        query.append((key, "<redacted>" if key.lower() in sensitive else value))
    return urlunsplit((parts.scheme, f"{userinfo}{host}{port}", parts.path, urlencode(query), ""))


def resolve_host_ips(host: str, port: int) -> list[str]:
    results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips = sorted({item[4][0] for item in results})
    return ips
