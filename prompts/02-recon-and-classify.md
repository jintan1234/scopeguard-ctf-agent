# Recon and classify

```text
Continue task <TASK_ID>.

Perform bounded recon:

- identify the application or file type;
- inspect attachments without executing untrusted code on the host;
- capture relevant HTTP/browser/file evidence;
- record raw artifacts and SHA-256;
- avoid broad fuzzing before identifying the interface.

Classify the challenge with:

- primary hypothesis and confidence;
- fallback hypothesis;
- supporting evidence;
- selected skill under skills/<category>/SKILL.md;
- at most three next actions.

Update the task to RECON, then CLASSIFIED.
Do not send exploit payloads in this step.
```
