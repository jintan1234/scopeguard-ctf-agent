# Security Policy

## Authorized use

ScopeGuard CTF Agent is intended for local labs, CTF challenges and systems
where the operator has explicit permission to test.

Do not use this project for:

- unauthorized scanning or exploitation;
- access to competition platforms or adjacent infrastructure outside a task
  scope;
- CAPTCHA bypass or account takeover outside a challenge;
- persistence, lateral movement or actions affecting other users without
  explicit confirmation.

## Reporting a vulnerability

Please report security issues privately to the repository owner. Include:

- affected file or tool;
- reproduction steps;
- impact;
- whether the issue can exceed an active scope;
- a minimal suggested fix when possible.

Do not publish an exploit that bypasses the authorization or sandbox boundary
before a fix is available.

## Current security boundaries

- explicit authorization is required to create a task;
- target hosts, ports and schemes are stored in `scope.json`;
- HTTP redirects are checked hop-by-hop;
- Playwright traffic is routed through a local scope proxy;
- Docker profiles default to `--network none`;
- task paths and archive extraction paths are checked;
- browser profiles and large third-party runtimes are excluded from Git;
- broker tokens are generated locally and ignored by Git.

## Known hardening items

DNS rebinding prevention, full IPv6 metadata blocking and cross-platform
launchers should be reviewed before using the project for high-assurance
automation. See `docs/THREAT_MODEL.md`.
