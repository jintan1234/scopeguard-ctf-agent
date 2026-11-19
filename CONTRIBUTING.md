# Contributing

Contributions are welcome when they preserve the project's authorization and
evidence boundaries.

## Development workflow

1. Create a branch.
2. Keep new network-facing behavior behind task scope validation.
3. Add tests for rejected as well as successful requests.
4. Never commit real challenge artifacts, credentials, cookies, Flags or
   browser profiles.
5. Run the test suite.
6. Open a pull request describing the security boundary affected by the change.

## Local tests

```bash
PYTHONPATH=tools python -m unittest discover -s tests -v
```

## Test expectations

Any change to HTTP, Playwright proxying, Docker, file extraction, task state or
Flag verification must include a negative test proving out-of-scope behavior
is rejected.

## Code style

- Prefer Python standard library unless a dependency materially improves the
  analysis capability.
- Keep optional dependencies lazy-imported where possible.
- Use UTF-8 and repository-relative paths.
- Do not put machine-specific absolute paths in source or documentation.
