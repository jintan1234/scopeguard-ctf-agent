# ScopeGuard CTF Agent

An evidence-first control plane for authorized CTF work with Codex and the
Model Context Protocol (MCP).

[中文说明](README.zh-CN.md)

This project focuses on the operational side of AI-assisted security work:

- explicit, per-task authorization and exact `host:port` scope;
- HTTP and browser traffic constrained to the active task;
- isolated Docker profiles for analysis, pwn, reverse, web, crypto and remote
  desktop tooling;
- bounded tool calls, wall time, retries and no-progress loops;
- hashed artifacts, command/evidence ledgers and reproducible reports;
- controlled Flag verification levels instead of "regex matched" claims.

The project is not a fully autonomous CTF solver. Codex remains responsible for
hypotheses, technique selection and exploit development. The control plane
makes those operations narrower, observable and auditable.

## What is included

- `tools/ctf_core`: task, scope, evidence, HTTP, file, Flag and report logic.
- `mcp/ctf-control`: 31-tool MCP server for the core workflow.
- `mcp/playwright`: Playwright MCP launcher with a task-scope egress proxy and
  browser-action budget bridge.
- `mcp/docker-broker`: token-authenticated local Docker control plane.
- `docker`: Dockerfiles for the supported sandbox profiles.
- `skills`: category guidance for orchestrator, web, pwn, reverse, crypto,
  forensics, misc and OSINT tasks.
- `prompts`: copy-ready authorization, recon, exploitation, verification,
  reporting and handoff prompts.
- `scripts/bootstrap.ps1` and `scripts/bootstrap.sh`: one-command setup.
- `docs/WORKFLOW.md`: end-to-end workflow from task creation to report.
- `examples/case-studies`: sanitized real-world case studies.
- `examples/quickdemo`: offline end-to-end demo.
- `tests`: local regression tests for scope, budgets, evidence and reporting.

## Requirements

- Python 3.11 or newer.
- Git.
- Docker Desktop or Docker Engine for sandbox profiles.
- Codex with project-scoped MCP configuration.
- Node.js 20 or newer for the Playwright MCP layer.

The core control plane uses only the Python standard library. Optional
file/image/reverse-analysis helpers use the packages in
`requirements-core.txt`.

## One-command setup

Install the external prerequisites first: Python 3.11+, Node.js 20+, Docker,
Git and Codex.

Windows PowerShell:

```powershell
cd "C:\path\to\scopeguard-ctf-agent"
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1 -ConfigureCodex
```

This command:

1. creates `.venv`;
2. installs Python dependencies and the package;
3. runs `npm ci`;
4. installs Chromium into the repository-local Playwright cache;
5. creates the project `.codex/config.toml` with the real project path;
6. runs 32 tests;
7. runs the offline end-to-end demo.

Optional switches:

```text
-TrustProject    add the current path to the user-level Codex trust config
-BuildAnalysis   build the analysis Docker image
-SkipBrowser     skip Playwright dependency/browser installation
```

Linux/macOS:

```bash
cd /path/to/scopeguard-ctf-agent
bash scripts/bootstrap.sh --configure-codex
```

Available Linux options:

```text
--trust-project
--build-analysis
--skip-browser
```

After bootstrapping, keep the Docker broker running in a second terminal:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-docker-broker.ps1
```

Then start Codex from the repository:

```powershell
codex
```

Use [`prompts/00-operator.zh-CN.md`](prompts/00-operator.zh-CN.md) or
[`prompts/01-start-authorized-task.md`](prompts/01-start-authorized-task.md)
for the first task.

Detailed troubleshooting is in [`docs/BOOTSTRAP.md`](docs/BOOTSTRAP.md).

### Included setup scripts

| Script | Purpose |
| --- | --- |
| `bootstrap.ps1` / `bootstrap.sh` | Create the virtual environment, install dependencies, install Chromium, configure MCP, run tests and demo |
| `enable-codex-mcp.ps1` / `.sh` | Render the project-scoped Codex MCP config with the real path |
| `trust-project.ps1` / `.sh` | Optionally add user-level Codex project trust |
| `start-docker-broker.ps1` | Start the restricted Docker broker |
| `restart-docker-broker.ps1` | Restart the broker |
| `check-toolchain.ps1` | Probe every Docker profile |
| `doctor.ps1` | Print local environment status |
| `run-tests.ps1` | Run the regression suite |
| `wsl-install-runtime.sh` | Install optional WSL/Linux tooling |
| `wsl-finalize-tools.sh` | Create optional tool wrappers |
| `wsl-tool-check.sh` | Verify optional WSL/Linux tools |

## Quick start

### 1. Create a virtual environment

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements-core.txt
& .\.venv\Scripts\python.exe -m pip install -e .
```

Linux/macOS:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -r requirements-core.txt
./.venv/bin/python -m pip install -e .
```

### 2. Run the tests

Windows:

```powershell
$env:CTF_PYTHON = (Resolve-Path ".\.venv\Scripts\python.exe").Path
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-tests.ps1
```

Linux/macOS:

```bash
PYTHONPATH=tools ./.venv/bin/python -m unittest discover -s tests -v
```

Expected result: 32 tests passing.

Run the offline end-to-end demo:

```bash
python examples/quickdemo/demo.py
```

It creates a task, decodes a synthetic fixture, verifies a candidate and
generates a report without making network requests.

### 3. Install Playwright MCP

```bash
cd mcp/playwright
npm ci
export PLAYWRIGHT_BROWSERS_PATH="$PWD/browsers"
npx playwright install chromium
cd ../..
```

Set the browser executable when the local launcher cannot discover it:

Windows PowerShell:

```powershell
$env:CTF_PLAYWRIGHT_BROWSER_EXECUTABLE = "C:\path\to\chrome-headless-shell.exe"
```

Linux/macOS:

```bash
export CTF_PLAYWRIGHT_BROWSER_EXECUTABLE="$HOME/.cache/ms-playwright/chromium-*/chrome-linux/chrome"
```

### 4. Configure Codex MCP

Windows uses `config/codex-mcp.project.toml.example`; Linux uses
`config/codex-mcp.project.linux.toml.example`. The bootstrap and
`enable-codex-mcp` scripts replace `<PROJECT_ROOT>` automatically.

Do not copy an absolute path from another machine.

### 5. Start the Docker broker

Windows:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-docker-broker.ps1
```

Linux/macOS:

```bash
./.venv/bin/python mcp/docker-broker/broker.py \
  --root "$PWD" \
  --host 127.0.0.1 \
  --port 8765
```

The broker stores its random bearer token in
`config/docker-broker-token`. The token file is ignored by Git.

## Task workflow

```text
SCOPED -> RECON -> CLASSIFIED -> EXPLOITING -> VERIFIED -> REPORTED
```

See [`docs/WORKFLOW.md`](docs/WORKFLOW.md) for the full process and
[`prompts/`](prompts/) for copy-ready Codex operator prompts.

Create a task with an explicit target URL and authorization:

```powershell
$env:PYTHONPATH = "tools"
& .\.venv\Scripts\python.exe -m ctf_core.cli task-create `
  --target "http://127.0.0.1:3000/" `
  --instruction "Analyze this locally authorized lab and verify the result." `
  --authorized
```

Every task directory contains:

```text
task.json
scope.json
state.json
notes.md
evidence/commands.jsonl
evidence/events.jsonl
artifacts/
exploit/
```

## Scope model

The task manifest is authoritative. A task must contain `authorized=true` and
an exact set of allowed hosts, ports and schemes before target-facing tools can
run. Redirects are checked per hop. Browser traffic is routed through the
active-scope proxy. Sandbox containers default to `--network none`.

The current implementation validates DNS resolution before a request. A
hardening release should additionally pin the validated IP at connection time
to eliminate DNS rebinding races. See `docs/THREAT_MODEL.md`.

## Flag assurance

Supported labels:

- `platform_verified`
- `local_validator_verified`
- `reproducible_evidence`
- `format_only`
- `rejected`

Only the first three may be presented as a found Flag. A string that merely
looks like a Flag is not a successful solve.

## Case studies

The repository includes sanitized technical case studies:

- [`examples/case-studies/index.json`](examples/case-studies/index.json)
- [`examples/case-studies/fruit-ret2libc`](examples/case-studies/fruit-ret2libc/)
- [`examples/case-studies/easy-dex`](examples/case-studies/easy-dex/)
- [`examples/case-studies/go-vm`](examples/case-studies/go-vm/)
- [`examples/case-studies/sql-injection-cves`](examples/case-studies/sql-injection-cves/)
- [`examples/case-studies/sqli-labs-less1`](examples/case-studies/sqli-labs-less1/)
- [`examples/case-studies/easyida`](examples/case-studies/easyida/)
- [`examples/case-studies/crypto-base64-xor`](examples/case-studies/crypto-base64-xor/)
- [`examples/case-studies/misc-fake-zip`](examples/case-studies/misc-fake-zip/)

They preserve the real internal lab IPs, verified Flags, commands, payload
structures and scripts. Personal platform credentials and local machine paths
are excluded. Each case includes an evidence example.

## Safety

Use this project only against systems you own or are explicitly authorized to
test. The project does not include competition-platform adapters, CAPTCHA
bypassing, or an authorization-free scanning mode.

See `SECURITY.md` and `AGENTS.md` before adding new network-facing tools.

## Acknowledgements

Special thanks to Conly-Zy for the original CTF-Agent project.

Original repository:
https://github.com/Conly-Zy/CTF-Agent

This project was developed independently, with inspiration from the original
project's approach to AI-assisted CTF solving, multi-agent workflows, and
security challenge organization.

We appreciate the original author's work and contribution to the CTF
open-source community.

The original project's license could not be independently verified at the time
of writing.

All third-party components and any code derived from external projects remain
subject to their respective licenses.

Additional third-party notices are recorded in `THIRD_PARTY_NOTICES.md`,
`NOTICE`, and `docs/upstream/`. Source and license audit details are in
`docs/upstream/CONLY_CTF_AGENT_AUDIT.md`.

## Status

This is an early public release. The core control plane and tests are stable
locally. Browser automation and Docker tooling remain environment-dependent.

The project is licensed under Apache-2.0. MIT and GPL-2.0 material from
upstream projects remains under its original license; see `NOTICE`,
`THIRD_PARTY_NOTICES.md` and `licenses/`.
