# ctf-control MCP

Minimal stdio Model Context Protocol server for local task, scope, file, HTTP, PCAP, evidence, flag and report operations.

The current server exposes 31 tools. Control-loop tools include workflow state,
pre-execution budgets, agent evidence recording, flag scanning/platform
submission, OpenSSH command execution and a fixed SSH-to-HTTP relay.

## Run

Windows:

```text
<PROJECT_ROOT>\mcp\ctf-control\server.cmd
```

Linux/macOS:

```text
<PROJECT_ROOT>/mcp/ctf-control/server.sh
```

The launcher uses `%CTF_PYTHON%` when set and otherwise the verified local Python 3.12 installation. It sets `PYTHONPATH` to the project `tools` directory.

## Protocol

Implemented requests:

- `initialize`
- `notifications/initialized`
- `ping`
- `tools/list`
- `tools/call`

The server writes diagnostics only to stderr. Tool results include both text JSON and `structuredContent`.

## Global Codex registration

This is a phase 4 activity. Before adding the server to `~/.codex/config.toml`, back up the file and verify the current CLI behavior. Phase 3 intentionally does not alter global configuration.
