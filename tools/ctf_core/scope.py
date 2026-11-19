from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .util import PolicyError, read_json, resolve_host_ips


BLOCKED_HOSTS = {
    "metadata.google.internal",
    "metadata",
    "instance-data",
}

BLOCKED_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
}


def _normalise_host(value: str) -> str:
    host = value.strip().lower().rstrip(".")
    if not host:
        raise PolicyError("empty host")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


@dataclass(frozen=True)
class ScopePolicy:
    authorized: bool
    target_url: str
    allowed_hosts: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    allowed_schemes: tuple[str, ...]
    allowed_redirect_hosts: tuple[str, ...] = ()
    user_constraints: tuple[str, ...] = ()

    @classmethod
    def from_task(cls, task_dir: Path) -> "ScopePolicy":
        raw = read_json(task_dir / "scope.json")
        return cls(
            authorized=bool(raw.get("authorized")),
            target_url=str(raw["target_url"]),
            allowed_hosts=tuple(_normalise_host(h) for h in raw.get("allowed_hosts", [])),
            allowed_ports=tuple(int(p) for p in raw.get("allowed_ports", [])),
            allowed_schemes=tuple(str(s).lower() for s in raw.get("allowed_schemes", [])),
            allowed_redirect_hosts=tuple(
                _normalise_host(h) for h in raw.get("allowed_redirect_hosts", [])
            ),
            user_constraints=tuple(str(v) for v in raw.get("user_constraints", [])),
        )

    def validate_url(self, url: str, *, redirect: bool = False) -> dict[str, Any]:
        if not self.authorized:
            raise PolicyError("task is not marked as authorized")
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in self.allowed_schemes:
            raise PolicyError(f"scheme is not allowed: {scheme}")
        if not parts.hostname:
            raise PolicyError("URL has no hostname")
        host = _normalise_host(parts.hostname)
        if host in BLOCKED_HOSTS:
            raise PolicyError(f"blocked metadata host: {host}")
        hosts = set(self.allowed_hosts)
        if redirect:
            hosts.update(self.allowed_redirect_hosts)
        if host not in hosts:
            raise PolicyError(f"host is outside the authorized scope: {host}")
        port = parts.port or _default_port(scheme)
        endpoint = self.validate_endpoint(host, port)
        return {
            "url": url,
            "scheme": scheme,
            "host": host,
            "port": port,
            "resolved_ips": endpoint["resolved_ips"],
        }

    def validate_endpoint(self, host: str, port: int) -> dict[str, Any]:
        if not self.authorized:
            raise PolicyError("task is not marked as authorized")
        host = _normalise_host(host)
        if host in BLOCKED_HOSTS:
            raise PolicyError(f"blocked metadata host: {host}")
        if host not in set(self.allowed_hosts):
            raise PolicyError(f"host is outside the authorized scope: {host}")
        port = int(port)
        if self.allowed_ports and port not in self.allowed_ports:
            raise PolicyError(f"port is outside the authorized scope: {port}")
        ips = resolve_host_ips(host, port)
        if not ips:
            raise PolicyError(f"host did not resolve: {host}")
        for value in ips:
            ip = ipaddress.ip_address(value.split("%", 1)[0])
            if ip in BLOCKED_IPS:
                raise PolicyError(f"host resolves to a blocked metadata address: {ip}")
        return {
            "host": host,
            "port": port,
            "resolved_ips": ips,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorized": self.authorized,
            "target_url": self.target_url,
            "allowed_hosts": list(self.allowed_hosts),
            "allowed_ports": list(self.allowed_ports),
            "allowed_schemes": list(self.allowed_schemes),
            "allowed_redirect_hosts": list(self.allowed_redirect_hosts),
            "user_constraints": list(self.user_constraints),
        }


def build_scope(
    target_url: str,
    *,
    authorized: bool,
    allowed_hosts: list[str] | None = None,
    allowed_ports: list[int] | None = None,
    allowed_schemes: list[str] | None = None,
    allowed_redirect_hosts: list[str] | None = None,
    user_constraints: list[str] | None = None,
) -> dict[str, Any]:
    if not authorized:
        raise PolicyError("explicit authorization is required")
    parts = urlsplit(target_url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise PolicyError("target must be an absolute http(s) URL")
    host = _normalise_host(parts.hostname)
    scheme = parts.scheme.lower()
    port = parts.port or _default_port(scheme)
    hosts = [_normalise_host(value) for value in (allowed_hosts or [host])]
    if host not in hosts:
        hosts.insert(0, host)
    ports = [int(value) for value in (allowed_ports or [port])]
    schemes = [str(value).lower() for value in (allowed_schemes or [scheme])]
    scope = ScopePolicy(
        authorized=True,
        target_url=target_url,
        allowed_hosts=tuple(dict.fromkeys(hosts)),
        allowed_ports=tuple(dict.fromkeys(ports)),
        allowed_schemes=tuple(dict.fromkeys(schemes)),
        allowed_redirect_hosts=tuple(
            _normalise_host(value) for value in (allowed_redirect_hosts or [])
        ),
        user_constraints=tuple(user_constraints or []),
    )
    scope.validate_url(target_url)
    return scope.to_dict()
