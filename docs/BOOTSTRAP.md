# Bootstrap and first run

## 1. Install external prerequisites

The repository cannot install Codex, Docker Desktop, Git or Node.js for the
host. Install them first.

Minimum versions:

```text
Python 3.11+
Node.js 20+
Docker Engine or Docker Desktop
Git
Codex
```

## 2. Run the bootstrap

Windows:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1 -ConfigureCodex
```

Linux/macOS:

```bash
bash scripts/bootstrap.sh --configure-codex
```

If the project path is not already trusted by Codex, add:

```text
Windows: -TrustProject
Linux:   --trust-project
```

This modifies the user-level Codex configuration with a backup. It is optional
and explicit.

## 3. Start the Docker broker

Windows:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-docker-broker.ps1
```

Linux/macOS:

```bash
./.venv/bin/python mcp/docker-broker/broker.py \
  --root "$PWD" --host 127.0.0.1 --port 8765
```

Keep this process running.

## 4. Verify the toolchain

Create a local task first if no active scope exists:

```powershell
$env:PYTHONPATH = "tools"
& .\.venv\Scripts\python.exe -m ctf_core.cli task-create `
  --target "http://127.0.0.1:3000/" `
  --instruction "Local toolchain check only." `
  --authorized
```

Then:

```powershell
$env:CTF_PYTHON = (Resolve-Path ".\.venv\Scripts\python.exe").Path
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\check-toolchain.ps1
```

## 5. Start Codex

```powershell
codex
```

The project-scoped `.codex/config.toml` registers:

```text
ctf_control
playwright
```

## 6. Start the first task

Use `prompts/00-operator.zh-CN.md` and replace every placeholder with the
authorized target and exact scope.

The expected workflow is:

```text
SCOPED -> RECON -> CLASSIFIED -> EXPLOITING -> VERIFIED -> REPORTED
```

## Script reference

| Script | Purpose |
| --- | --- |
| `scripts/bootstrap.ps1` | Windows one-command initialization |
| `scripts/bootstrap.sh` | Linux/macOS one-command initialization |
| `scripts/enable-codex-mcp.ps1` | Generate project Codex MCP config |
| `scripts/enable-codex-mcp.sh` | Linux/macOS Codex MCP config |
| `scripts/trust-project.ps1` | Optionally add user-level Codex trust |
| `scripts/trust-project.sh` | Linux/macOS Codex trust helper |
| `scripts/start-docker-broker.ps1` | Start the restricted Docker broker |
| `scripts/restart-docker-broker.ps1` | Restart the broker |
| `scripts/check-toolchain.ps1` | Run all Docker profile probes |
| `scripts/doctor.ps1` | Print local environment status |
| `scripts/run-tests.ps1` | Run the Python regression tests |
| `scripts/preflight-public-release.ps1` | Scan the public tree before pushing |
| `scripts/wsl-install-runtime.sh` | Install optional WSL tools |
| `scripts/wsl-finalize-tools.sh` | Create optional tool wrappers |
| `scripts/wsl-tool-check.sh` | Verify optional WSL tools |

## Common failures

### Playwright browser missing

Run with the repository-local browser cache:

```powershell
cd mcp\playwright
$env:PLAYWRIGHT_BROWSERS_PATH = (Join-Path (Get-Location) "browsers")
& npm.cmd ci
& npx.cmd playwright install chromium
```

### Docker broker unavailable

Confirm Docker is running, then restart the broker:

```powershell
docker version
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\restart-docker-broker.ps1
```

### Codex does not see the MCP servers

1. Run `scripts/enable-codex-mcp.ps1 -Confirm`.
2. Confirm `.codex/config.toml` contains the real project absolute path.
3. Start a new Codex thread.
4. If needed, add project trust with `scripts/trust-project.ps1 -Confirm`.
