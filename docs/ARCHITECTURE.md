# Architecture

```text
User / Codex
    |
    +-- AGENTS.md and project instructions
    |
    +-- ctf-control MCP
    |      |
    |      +-- TaskManager: task.json, scope.json, state.json
    |      +-- EvidenceLedger: events.jsonl, commands.jsonl, artifacts
    |      +-- HTTP client: redirect-aware scope checks
    |      +-- File analysis: ZIP, image, PCAP, crypto, bytecode
    |      +-- Flag operations: scan, verify, submit
    |      +-- Report generator: report.md, result.json
    |
    +-- Playwright MCP
    |      |
    |      +-- browser-action budget bridge
    |      +-- local HTTP/CONNECT scope proxy
    |      +-- isolated browser profile
    |
    +-- Restricted Docker Broker
           |
           +-- analysis
           +-- pwn
           +-- reverse
           +-- web
           +-- crypto
           +-- remote
```

## Trust boundaries

1. Prompt instructions are advisory; file and network checks are technical.
2. `scope.json` is the source of truth for target authorization.
3. Docker containers do not receive host credentials or the Docker socket.
4. Browser traffic is forced through the scope proxy.
5. Evidence is written under one task directory and hashed before reporting.

## Task state

```text
SCOPED
  -> RECON
  -> CLASSIFIED
  -> EXPLOITING
  -> VERIFIED
  -> REPORTED
```

Blocked or budget-exhausted tasks remain preserved. Failed attempts are
evidence and must not be deleted.

## Evidence model

Each artifact record contains:

- relative path;
- SHA-256;
- size;
- kind;
- source tool;
- timestamp.

Reports are generated from the recorded state and evidence ledger, not from
unsaved model memory.
