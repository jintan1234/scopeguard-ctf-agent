---
name: ctf-orchestrator
description: Use when Codex receives an authorized CTF target URL, attachment set, or solving instruction and must classify the challenge, choose tools, execute a bounded solving loop, verify a flag, and produce an evidence-backed report.
---

# CTF Orchestrator

## Entry checklist

1. Extract the exact target and user constraints.
2. Create a task through `ctf_task_create` or `python -m ctf_core.cli task-create`.
3. Read the returned task path and `scope.json`.
4. Call `ctf_task_update` to enter `RECON`.
5. List attachments and inspect file types without executing them.
6. Read `config/tool-catalog.json`; do not assume planned tools exist.
7. Set an internal plan with at most 3 initial hypotheses.

## Classification

Score candidates using observed evidence:

- Web: pages, routes, HTTP APIs, cookies, sessions, parameters, uploads.
- Misc: archive, encoded text, image/audio/PDF/Office, unknown file.
- Reverse: PE/ELF/APK/JAR/bytecode with behavior hidden in code.
- Pwn: native service, binary, network port, crash or memory corruption.
- Crypto: keys, mathematical parameters, ciphertext, oracle, PRNG.
- Forensics: PCAP, memory/disk image, logs, timeline, deleted data.
- OSINT: challenge explicitly requires public information tied to the task.

Choose a primary and a fallback. State the evidence, not just a label.
Record both through `ctf_task_update` and move the task to `CLASSIFIED`.

## Execution loop

For each iteration:

1. State the current hypothesis.
2. Select the cheapest tool that can falsify it.
3. Execute with a timeout and bounded output.
4. Store large output as an artifact.
5. Summarize new evidence.
6. Update or reject the hypothesis.
7. Change technique after repeated identical failure.

Record commands or console actions that bypass ctf-control with
`ctf_evidence_record`; register their output files with
`ctf_register_artifact`. Save HTTP, browser, OCR and terminal output before
calling `ctf_flag_scan`.

Avoid dumping entire pages, binaries or PCAPs into context. Search and extract.

## Web priority

1. Playwright navigation and accessibility snapshot.
2. Network requests and response bodies.
3. Source, JavaScript and API discovery.
4. Controlled request mutations.
5. Exploit verification.

## File priority

1. `ctf_file_inspect`: size, hash, magic, entropy, strings, ZIP members.
2. Type-specific skill.
3. Sandbox only if parsing or execution is risky.

## Flag discipline

Register every plausible candidate with its source. Do not mark a flag verified from format alone. Use a platform/local validator or a proof artifact that actually contains the candidate.

Use `ctf_flag_submit` only with an in-scope submission endpoint and a mandatory
response-success regex. Its `platform_verified` result must reference the saved
acceptance artifact.

## Stop conditions

Stop and report when:

- wall-time or tool-call budget expires;
- max no-progress count is reached;
- a required attachment is missing;
- scope must expand beyond explicit authorization;
- a tool or dependency is missing and no safe alternative is available;
- the flag is verified and minimum reproducibility evidence is recorded.

## Final output

Generate `report.md` and `result.json`. Include exact commands, scripts, artifacts, evidence hashes, candidate/verification status and unresolved work.
