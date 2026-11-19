# Upstream source map

This file records the intended provenance of public-release material. It is a
technical audit aid, not legal advice.

| Public path | Upstream | Upstream material | State |
| --- | --- | --- | --- |
| `AGENTS.md` | Heimdall | `AGENTS.md`, observer/workflow concepts | Adapted |
| `skills/orchestrator/SKILL.md` | Heimdall / BinaryPilot | workflow, hypothesis and skill selection concepts | Adapted |
| `skills/web/SKILL.md` | BinaryPilot | Web skill structure and technique inventory | Adapted |
| `skills/pwn/SKILL.md` | BinaryPilot | Pwn skill structure and technique inventory | Adapted |
| `skills/crypto/SKILL.md` | BinaryPilot | Crypto skill concepts | Adapted |
| `skills/reverse/SKILL.md` | BinaryPilot | Reverse skill concepts | Adapted |
| `skills/forensics/SKILL.md` | BinaryPilot / Heimdall | tooling and evidence concepts | Adapted |
| `skills/misc/SKILL.md` | BinaryPilot | challenge classification and file analysis | Adapted |
| `skills/osint/SKILL.md` | BinaryPilot | OSINT boundary concepts | Adapted |
| `prompts/` | BinaryPilot / Heimdall / independent Codex workflow | prompt decomposition and exploration-loop ideas | Design-level adaptation; no Conly copy established |
| `docs/WORKFLOW.md` | Heimdall / independent Codex workflow | observer and evidence concepts | Design-level adaptation; no Conly copy established |
| `docker/` | Veria / BinaryPilot | tool inventory and sandbox concepts | Adapted |
| `mcp/playwright/` wrapper | Playwright MCP | MCP browser integration | Wrapped dependency |
| `mcp/computer-use/README.md` | Hybrid Computer Use | desktop-control integration concepts | Adapted |
| `docker/analysis/third_party/stegseek-source.zip` | StegSeek | complete source archive | Vendored, GPL-2.0 |

## Verification required

For every row marked `Adapted`, compare against the exact upstream commit and:

1. preserve the upstream copyright/license text;
2. add a comment such as `Adapted from <project> <commit>; modified for
   ScopeGuard CTF Agent`;
3. remove upstream platform-specific constants, credentials and unsafe
   defaults;
4. record the upstream path in this table.

The current mapping is high-level. If whole files were copied, add a
file-by-file row before publication.

`Conly-Zy/CTF-Agent` is currently unavailable. No reliable statement about
direct copying or porting from that repository can be made. Pojun is a related
public project but is not established as the same source tree.
