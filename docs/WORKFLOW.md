# Workflow

This document describes the intended end-to-end workflow for a single
authorized challenge.

## 1. Input contract

The user should provide:

- the exact target URL;
- allowed hosts and ports;
- optional attachments;
- expected Flag format;
- prohibited actions;
- time or tool-call limits.

If the scope is ambiguous, do not start target-facing work.

## 2. Create the task

```bash
ctf-agent task-create \
  --target "http://127.0.0.1:3000/" \
  --instruction "Solve this authorized local challenge." \
  --authorized
```

The task directory becomes the only writable workspace for the challenge.

```text
task.json
scope.json
state.json
notes.md
input/
artifacts/
exploit/
evidence/
```

## 3. Recon

Goals:

- fingerprint the application or file;
- identify attachments and protocols;
- save raw evidence;
- avoid broad fuzzing before understanding the interface.

At this point move the workflow state to `RECON`.

## 4. Classify

Record:

- primary hypothesis;
- fallback hypothesis;
- selected skill;
- evidence supporting the classification;
- next three actions.

Move the task to `CLASSIFIED`.

## 5. Exploitation loop

For every iteration:

1. State the current hypothesis.
2. Select the cheapest tool capable of disproving it.
3. Run a bounded action.
4. Save raw output as an artifact.
5. Record the command or browser action.
6. Update the hypothesis.
7. Change technique after repeated identical failure.

Move the task to `EXPLOITING`.

## 6. Evidence

Every meaningful result should have:

- an exact command;
- a timestamp;
- a response or script output;
- an artifact path;
- a SHA-256 hash;
- a source tool.

Failed attempts are retained. Never remove contradictory evidence.

## 7. Flag verification

Candidate discovery is not a solve.

Use one of:

- `platform_verified`;
- `local_validator_verified`;
- `reproducible_evidence`.

`format_only` and `rejected` are not successful results.

Move the task to `VERIFIED` only after the assurance level is supported by a
saved artifact.

## 8. Report

Generate:

- `report.md`;
- `result.json`.

The report should contain the technical approach, vulnerability, commands,
scripts, evidence hashes, rejected candidates and unresolved issues.

Move the task to `REPORTED`.

## 9. Stop conditions

Stop when:

- a Flag is verified and evidence is saved;
- the budget expires;
- the no-progress threshold is reached;
- the scope must expand;
- a required attachment is missing;
- no safe tool alternative exists;
- the next action would be destructive or affect other users.

The final state should explain the exact blocker rather than continue
unbounded retries.

## Prompt sequence

Use the templates in `prompts/` in this order:

1. `01-start-authorized-task.md`
2. `02-recon-and-classify.md`
3. `03-bounded-exploit-loop.md`
4. `04-verify-and-report.md`
5. `05-stop-and-handoff.md` when blocked
