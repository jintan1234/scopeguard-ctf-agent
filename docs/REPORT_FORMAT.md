# Report format

Each completed task produces `report.md` and `result.json`.

## `report.md`

Recommended sections:

1. Scope and objective.
2. Flag and assurance level.
3. Challenge type and confidence.
4. Recon evidence.
5. Hypotheses.
6. Technical approach.
7. Exact commands and scripts.
8. Artifact paths and SHA-256.
9. Failed attempts.
10. Candidate Flags and rejection reason.
11. Unresolved issues.

## `result.json`

Minimum fields:

```json
{
  "task_id": "example",
  "target": "http://127.0.0.1:8080/",
  "challenge_type": "web",
  "success": false,
  "flag": null,
  "assurance": "unverified",
  "candidate_flags": [],
  "commands": [],
  "artifacts": [],
  "summary": "",
  "unresolved": []
}
```

The report generator should derive these fields from recorded task state and
the evidence ledger.
