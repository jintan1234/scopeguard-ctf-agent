# Conly-Zy/CTF-Agent provenance audit

Audit date: 2026-11-19

## Executive result

No reliable evidence of direct source-code copying from
`Conly-Zy/CTF-Agent` was found in this repository.

This does **not** prove the project never referenced its design. The original
repository is currently unavailable, so a definitive similarity audit against
that exact source cannot be performed.

Current classification:

- Direct-copy evidence from Conly-Zy/CTF-Agent: **not found**
- Modified-source evidence from Conly-Zy/CTF-Agent: **not found**
- Design-reference possibility: **plausible but not proven**
- Original source availability: **unavailable**
- Original license: **UNKNOWN**

## Availability checks

Checked on 2026-11-19:

```text
https://github.com/Conly-Zy/CTF-Agent
```

Result:

```text
HTTP 404
```

Additional checks:

- GitHub API repository lookup: 404
- GitHub account public repository listing: no `CTF-Agent` repository
- GitHub repository search: no matching repository
- Local research directories: no Conly-Zy/CTF-Agent source
- Internet Archive lookup: unavailable from the audit network

The GitHub account currently exposes a fork of `Pojun`:

```text
https://github.com/Conly-Zy/Pojun
Current upstream: https://github.com/chu0119/Pojun
Audited commit: 2230279b7e6eef1fdf2b008dda06664782e3b9c4
License: AGPL-3.0
```

`Pojun` is not automatically the same source tree as the unavailable
`CTF-Agent` repository. Its license cannot be used as the license of
`CTF-Agent`.

## Local comparison corpus

The following upstream source snapshots were available locally under
`E:\ctf比赛\research\upstream`:

- BinaryPilot
- Heimdall
- Veria Labs CTF-Agent
- Hybrid Computer Use
- Playwright MCP
- CLI-Anything

No local `Conly-Zy/CTF-Agent` snapshot was present.

## Similarity checks

### Exact file hashes

Method:

- SHA-256 every non-generated file in the local upstream corpus;
- SHA-256 every non-generated file in the public release;
- compare exact hashes;
- ignore `.git`, `node_modules`, build outputs, caches and known license files.

Result:

```text
Exact source-file matches: 0
```

This result applies only to the available local upstream corpus. It does not
cover Conly-Zy/CTF-Agent.

### Normalized six-line blocks

Method:

- normalize whitespace;
- remove very short lines;
- create hashes for every six consecutive non-trivial lines;
- compare all local public-release files with the available upstream corpus.

Result:

```text
6-line block matches: 10
```

All detected matches were generic:

- Python standard-library import boilerplate in `tests/test_mcp.py`;
- generated npm dependency metadata in `mcp/playwright/package-lock.json`.

Example import block:

```python
from __future__ import annotations
import json
import os
import subprocess
import sys
import tempfile
```

This is not evidence of copied business logic.

No matching six-line blocks were found in BinaryPilot, Heimdall or Veria
application code.

## Component classification

### A. Agent orchestration

Local implementation:

- `AGENTS.md`: Codex is the primary orchestrator.
- `skills/orchestrator/SKILL.md`: hypothesis and tool-selection workflow.
- `tools/ctf_core/task.py`: task state, budget and tool-call sequencing.
- No separate sub-agent process, coordinator service or inter-agent message
  bus exists in the public release.

Comparison:

- Pojun contains a Go multi-agent autonomous pentest platform.
- The local project is a Python Codex/MCP control plane.
- No shared Go source or matching orchestration module was found.

Classification relative to Conly-Zy/CTF-Agent: **Category 5 - unknown due to
missing upstream source**.

### B. Knowledge management

Local implementation:

- evidence JSONL ledgers;
- task-local artifacts;
- report/result generation;
- no vector database, knowledge extraction service or writeup retrieval engine.

No matching knowledge-management module was found in the available upstream
corpus.

Classification relative to Conly-Zy/CTF-Agent: **Category 5 - unknown due to
missing upstream source**.

### C. Tool system

Local implementation:

- `tools/ctf_core/mcp_tools.py`, class `ToolRegistry`;
- tool definitions, dispatch and response envelopes;
- category guidance under `skills/`;
- HTTP, file, archive, crypto, Docker and remote helpers.

The generic concept "registered tools with names and schemas" is common and is
not sufficient to establish copying.

Classification:

- Conly-Zy/CTF-Agent: **Category 5 - unknown**
- Generic concept similarity: **Category 3 - design-level similarity only**

### D. Automation workflow

Local implementation:

- `SCOPED -> RECON -> CLASSIFIED -> EXPLOITING -> VERIFIED -> REPORTED`;
- tool budget and no-progress stopping;
- evidence recording;
- Flag assurance levels;
- report generation.

The workflow is documented in `docs/WORKFLOW.md` and implemented in
`tools/ctf_core/task.py`, `report.py` and `mcp_tools.py`.

The available local upstream corpus was used as design research, but no
business-code block match was found.

Classification relative to Conly-Zy/CTF-Agent: **Category 5 - unknown due to
missing upstream source**.

### E. Other components

- CLI: Python `argparse`.
- MCP JSON-RPC server: custom implementation in `mcp_server.py`.
- Playwright Scope Proxy: custom local proxy.
- Docker Broker: custom local token-authenticated broker.
- Web management interface: none.
- Configuration: local TOML/JSON.

No equivalent Conly-Zy/CTF-Agent implementation was available for comparison.

Classification: **Category 5 - unknown relative to the missing upstream
source**.

## Summary table

| Area | Direct copy | Modified source | Design reference | Independent implementation proven | Unknown |
| --- | --- | --- | --- | --- | --- |
| A. Agent orchestration | No evidence | No evidence | Possible | Not proven | Yes |
| B. Knowledge management | No evidence | No evidence | Possible | Not proven | Yes |
| C. Tool registry | No evidence | No evidence | Generic concept only | Not proven | Yes |
| D. Automation workflow | No evidence | No evidence | Possible | Not proven | Yes |
| E. CLI/MCP/Docker/docs | No evidence | No evidence | Possible | Not proven | Yes |

"Not proven" reflects the absence of Git history and the missing original
source. It does not mean the code was copied.

## License conclusion

The original `Conly-Zy/CTF-Agent` license is:

```text
UNKNOWN
```

Do not attribute MIT, Apache-2.0 or AGPL-3.0 to that repository without an
authoritative license record. The related `Pojun` project is AGPL-3.0, but its
license cannot be substituted for the unavailable CTF-Agent project.

The current ScopeGuard public release is licensed under Apache-2.0, with other
third-party license obligations recorded separately.
