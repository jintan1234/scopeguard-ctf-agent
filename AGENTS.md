# CTF Agent Operating Rules

This repository is a local, authorized CTF-solving workspace. Codex is the primary orchestrator. The project does not grant permission to test any target that the user has not explicitly named.

## Non-negotiable scope

1. A task must be created with `authorized=true` and the exact target URL before any target-facing operation.
2. Treat `scope.json` as authoritative. Do not contact a host, port, or scheme outside it.
3. Redirects, subresources, API calls, callbacks, and exploit connections must all remain in scope.
4. Never expand from an authorized app to the competition platform, other contestants, adjacent infrastructure, or unrelated internet hosts.
5. Destructive actions, persistence, lateral movement, or actions likely to affect other users require explicit confirmation before execution.
6. OSINT is allowed only for the challenge objective. Do not build profiles of unrelated people or collect personal information outside the competition.
7. Do not send secret environment variables, SSH keys, Codex credentials, API keys, cloud tokens, or browser profiles into challenge containers.

When scope is ambiguous, stop target-facing work and request a precise allowlist from the user.

## Required workflow

1. Read the user instruction and extract:
   - target URL;
   - explicit allowed hosts and ports;
   - attachments;
   - expected flag format;
   - prohibited actions;
   - time/call/resource constraints.
2. Create a task with `ctf_task_create` or:
   ```powershell
   python -m ctf_core.cli task-create ...
   ```
3. Perform light recon and record evidence before exploitation.
4. Classify the challenge with confidence and at least one fallback hypothesis.
5. Load only the relevant skill from `skills/<category>/SKILL.md`.
6. Prefer existing CLI/API/headless paths over GUI automation.
7. Record every meaningful command, response, artifact hash, and strategy change.
8. A flag is not verified merely because it matches `CTF{...}`.
9. Generate `report.md` and `result.json` only from recorded evidence.

Use `ctf_task_update` after SCOPED, RECON, CLASSIFIED and EXPLOITING
transitions. Store at least one primary and one fallback hypothesis at
classification time. Use `ctf_evidence_record` for meaningful shell,
browser-console, CDP or remote terminal actions that did not pass through a
dedicated evidence-producing tool. Use `ctf_flag_scan` on saved HTTP, browser,
OCR or terminal artifacts before declaring that no flag-like value was observed.

## Tool rules

- Use the tool catalog in `config/tool-catalog.json`.
- Never assume a tool is installed; run `ctf-agent tool-catalog` or inspect `last_verified_at`.
- Prefer the unified `ctf-control` tools for task, scope, file, HTTP, PCAP, flag and report operations.
- Use `ctf_remote_exec` only for an exact host and port present in `scope.json`.
  It requires OpenSSH host-key verification and does not provide password entry.
- Destructive remote commands require `destructive_confirmed=true`, which may be
  set only after explicit user confirmation.
- Use Playwright MCP for web exploration and network observation when available.
- The Playwright launcher routes browser traffic through the active task scope proxy. Do not bypass, disable, or replace it while solving an authorized task.
- Use Windows Computer Use only for software with no adequate CLI/API.
- Use Docker for untrusted files, reverse-engineering binaries, exploit development and web tooling.
- A tool missing from the catalog must not be silently installed while solving a task. Record the gap and continue with an available alternative.

## Evidence rules

- Task artifacts live under `challenges/current/<task_id>/`.
- Every artifact must have a SHA-256 and source tool.
- Large outputs must be written to files; only a bounded useful summary should be returned to the model.
- Keep failed attempts. Mark them as failed rather than deleting contradictory evidence.
- Never fabricate command output, execution, timing, tool availability, or exploit success.

## Flag assurance

Use these labels:

- `platform_verified`: accepted by an authorized challenge submission API.
- `local_validator_verified`: accepted by a challenge-specific local verifier.
- `reproducible_evidence`: exact flag is present in a recorded artifact and the recovery method can be rerun.
- `format_only`: only syntax matched; not a successful solve.
- `rejected`: explicitly rejected.

Only `platform_verified`, `local_validator_verified`, and `reproducible_evidence` may be presented as a found flag. Still distinguish them precisely.

For a platform submission endpoint, use `ctf_flag_submit` with an in-scope URL
and a mandatory success regex. Do not label a submission as
`platform_verified` without the saved successful response.

## Loop and budget discipline

- Defaults are in `config/budgets.toml`.
- Budget checks run before every task-scoped ctf-control tool.
- `BUDGET_EXHAUSTED`, `ACTION_RETRY_LIMIT`, `TASK_VERIFIED` and `TASK_REPORTED`
  are stop signals; change technique only when the error explicitly permits it.
- Respect maximum wall time, tool calls, response sizes and container limits.
- On repeated failure, change the hypothesis or tool; do not repeat an identical command.
- After the configured number of calls without new evidence, summarize blockers and stop.
- Do not use unlimited swarms or “never give up” prompts.

## Filesystem safety

- Never mount all of `E:\`, `C:\`, the user profile, `.codex`, `.docker`, `.ssh`, `.aws`, or API configuration into a challenge container.
- Mount challenge input read-only and a dedicated task workspace read-write.
- Do not execute untrusted binaries directly on Windows when a disposable Linux container or VM can analyze them.
- Do not modify global Codex configuration while solving a challenge.

## Completion report

The final report must include:

- verified flag and assurance level;
- challenge type and confidence;
- technical approach;
- vulnerability or key concept;
- tools and exact commands;
- scripts;
- evidence paths and hashes;
- candidate flags that were rejected or unverified;
- unresolved problems and the reason work stopped.
