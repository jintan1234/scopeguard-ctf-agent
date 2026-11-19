# Threat Model

## Assets

- authorization scope;
- target host and port boundaries;
- challenge attachments and extracted artifacts;
- browser cookies and task storage state;
- Docker host access;
- Flag evidence and verification status.

## Primary threats

### Out-of-scope requests

Mitigations:

- authorization required at task creation;
- host/port/scheme allowlist;
- redirect checks on each hop;
- Playwright proxy denies blocked destinations;
- metadata endpoints blocked.

### DNS rebinding

The current code resolves a hostname before making a request. A malicious DNS
server may answer differently when the HTTP client or browser proxy resolves
the host again.

Recommended fix:

- resolve once and validate every returned address;
- connect to the selected validated IP;
- retain the original `Host` header and TLS server name;
- use the same pinned-IP mechanism in the Playwright proxy.

Until this is fixed, do not treat the DNS layer as a hard security boundary in
hostile network environments.

### Path traversal and archive escape

Mitigations:

- task-relative path resolution;
- archive member validation;
- explicit artifact roots;
- no whole-drive or home-directory mounts.

### Agent loops

Mitigations:

- maximum tool calls and wall time;
- identical-action retry limit;
- consecutive no-progress limit;
- stop signals for verified or reported tasks.

### Evidence forgery or accidental claims

Mitigations:

- command and event ledgers;
- artifact SHA-256;
- separate candidate and verified Flag states;
- assurance labels;
- platform submission requires a saved success response.

## Non-goals

This project does not claim to be a hardened multi-tenant service. Run it as a
single-user local workspace.
