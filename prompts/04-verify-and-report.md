# Verify and report

```text
Review task <TASK_ID> only from recorded evidence.

1. Scan saved HTTP, browser, OCR and terminal artifacts for Flag candidates.
2. Register every candidate with its source artifact.
3. Do not claim success from format matching alone.
4. Use one of:
   - platform_verified;
   - local_validator_verified;
   - reproducible_evidence.
5. If no acceptable verification exists, leave the result unverified.
6. Generate report.md and result.json from the evidence ledger.

The report must include:

- verified Flag and assurance level, if any;
- challenge type and confidence;
- technical approach and vulnerability;
- exact commands and scripts;
- artifact paths and SHA-256 hashes;
- rejected candidates;
- unresolved issues and the reason work stopped.
```
