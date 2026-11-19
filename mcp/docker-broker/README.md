# Restricted Docker Broker

Codex's job sandbox cannot access Docker Desktop's named pipe. The broker runs as the signed-in user and exposes only a small local HTTP API.

## Start

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-docker-broker.ps1
```

Linux/macOS:

```bash
./.venv/bin/python mcp/docker-broker/broker.py \
  --root "$PWD" --host 127.0.0.1 --port 8765
```

The broker:

- binds only to `127.0.0.1:8765`;
- requires a random bearer token from `config/docker-broker-token`;
- allows only fixed image profile names;
- mounts only `input` read-only plus `artifacts`, `exploit`, and `work` from one exact task directory;
- optionally mounts the trusted `tool-runtime` directory read-only at `/opt/ctf-tools`;
- uses `--network none`, read-only rootfs, dropped capabilities, `no-new-privileges`, CPU/memory/pids/shm limits, and bounded execution;
- never mounts the host profile, Codex/Docker credentials, Docker socket, or whole drives.

## Operations

- `GET /health`
- `POST /v1/build`
- `POST /v1/create`
- `POST /v1/exec`
- `POST /v1/stop`

Network-enabled exploit profiles are intentionally not enabled yet. They require a separate authorized challenge network policy.
