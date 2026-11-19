# Playwright MCP

The launcher has a local smoke test that does not contact external targets.

## Installation

The package is pinned in `package.json`:

```text
@playwright/mcp 0.0.85
```

Run `npm ci` in this directory. Install a Chromium/headless-shell executable
separately and pass it through `CTF_PLAYWRIGHT_BROWSER_EXECUTABLE`.

Install Chromium into the repository-local browser cache:

```bash
export PLAYWRIGHT_BROWSERS_PATH="$PWD/browsers"
npx playwright install chromium
```

`server.cmd` and `server.sh` set the same cache path, so an explicit
`CTF_PLAYWRIGHT_BROWSER_EXECUTABLE` is optional.

```powershell
$env:CTF_PLAYWRIGHT_BROWSER_EXECUTABLE = "C:\path\to\chrome-headless-shell.exe"
```

## Launch

Windows:

```text
mcp\playwright\server.cmd
```

Linux/macOS:

```text
mcp/playwright/server.sh
```

Default properties:

- headless;
- Chromium headless shell by default;
- isolated in-memory profile;
- no unrestricted file access;
- 10 second action timeout;
- 30 second navigation timeout;
- no vision/pdf/devtools/unsafe-code capabilities;
- output under `challenges/current/browser-output`.

`--isolated` is intentional. It prevents reuse of the user's normal browser profile and avoids concurrent profile conflicts. A challenge requiring persistent login state should save/restore a task-specific storage-state file instead of attaching the normal profile.

## Scope proxy

`launcher.js` starts `scope_proxy.py` and passes it to Playwright as the HTTP proxy. Every HTTP request and HTTPS CONNECT is checked against the currently active task scope.

- Allowed traffic is forwarded.
- Out-of-scope destinations receive HTTP 403.
- Metadata hosts are blocked.
- Decisions are logged to `logs/playwright-scope-proxy.jsonl`.

The smoke test confirms both local navigation/click/network capture and an out-of-scope `example.com` request returning `403 Forbidden`.

## Budget bridge

`launcher.js` intercepts MCP `tools/call` messages before forwarding them to the
Playwright server.

- every browser action is checked against the active task budget;
- blocked actions receive an MCP tool error and are not forwarded;
- completed actions append `browser_tool_call` entries to the task ledger;
- snapshots, console logs and related output files are copied into the task
  `artifacts/browser-evidence` directory and hashed with SHA-256.

The local smoke test also asserts six counted browser calls, six browser events
and at least one hashed browser artifact.

## Smoke test

```powershell
& ..\..\.venv\Scripts\python.exe .\smoke_client.py
```

Linux/macOS:

```bash
../../.venv/bin/python smoke_client.py
```

The smoke test starts a local HTML/JSON server, negotiates MCP, navigates to
the local fixture, captures an accessibility snapshot and reads network
requests.
