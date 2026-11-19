# Third-party notices

This project incorporates ideas, workflow patterns, prompts, skills, tool
inventory material and/or modified source from the following projects.

## BinaryPilot

- Source: https://github.com/0xIDA/binarypilot
- Audited commit: `a62805414de9bf95ce282f739000e1347e58d653`
- License: Apache-2.0
- License copy: `licenses/BinaryPilot-Apache-2.0.txt`
- Used/adapted for: CTF skills, tool organization, Docker tooling concepts,
  agent workflow and documentation structure.
- Modification: adapted for Codex, MCP task state, strict scope checks,
  evidence ledgers and sanitized public examples.

## Heimdall

- Source: https://github.com/QiantangCredit/heimdall-agent
- Audited commit: `8a2e9c51096c63676f4d9f6a2345fc4a2f26912e`
- Copyright: 2026 Heimdall contributors
- License: MIT
- License copy: `licenses/Heimdall-MIT.txt`
- Used/adapted for: project rules, observer-style exploration state, workflow
  documentation and prompt structure.
- Modification: reduced to a local single-user Codex workflow; added scope,
  budget, evidence and report enforcement.

## Veria Labs CTF-Agent

- Source: https://github.com/verialabs/ctf-agent
- Audited commit: `3366d569557c4fda3fd153040632de65e255396d`
- Copyright: 2026 Veria Labs, Inc.
- License: MIT
- License copy: `licenses/Veria-Labs-CTF-Agent-MIT.txt`
- Used/adapted for: Docker tool environment inventory, tool capability ideas
  and smoke-test structure.
- Modification: restricted to local, authorized tasks and integrated with the
  Docker Broker and evidence ledger.

## Hybrid Computer Use

- Source: https://github.com/microsoft/Hybrid-Computer-Use
- Audited commit: `697d3fbda04cb322915866bab1aad79c726a61e3`
- Copyright: 2026 Hybrid Computer Use authors
- License: MIT
- License copy: `licenses/Hybrid-Computer-Use-MIT.txt`
- Used/adapted for: desktop-control documentation and integration notes.
- Modification: documentation only in this public distribution.

## CLI-Anything

- Source: https://github.com/HKUDS/CLI-Anything
- Audited commit: `34f519533bc175d2fe287ab8316b0dd99bb9cc43`
- License: Apache-2.0
- License copy: `licenses/CLI-Anything-Apache-2.0.txt`
- Used/adapted for: research into CLI wrapping and tool-generation concepts.
- Modification: no upstream application runtime is bundled.

## Playwright MCP

- Source: https://github.com/microsoft/playwright-mcp
- Audited commit: `78eca85361efb545a4c0f59b6140aef0721c5412`
- License: Apache-2.0
- License copy: `licenses/Playwright-MCP-Apache-2.0.txt`
- Runtime package: `@playwright/mcp` pinned in `mcp/playwright/package-lock.json`.
- Modification: wrapped with a task-scope HTTP proxy and browser-action budget
  bridge.

## StegSeek

- Source: https://github.com/RickdeJager/stegseek
- Vendored source archive:
  `docker/analysis/third_party/stegseek-source.zip`
- License: GPL-2.0
- License copy: `licenses/StegSeek-GPL-2.0.txt`
- Use: built as a separate executable in the analysis Docker image.

## Conly-Zy/CTF-Agent

- Source: https://github.com/Conly-Zy/CTF-Agent
- Status at audit time: HTTP 404; no local source snapshot was available
- Exact commit: UNKNOWN
- License: UNKNOWN
- Code-copy status: no reliable direct-copy comparison was possible
- Role: acknowledged as a research and design reference only

Do not attribute an MIT or AGPL license to this repository without the original
source or an authoritative license record. The name and engagement ideas are
acknowledged in the README, but no ownership of upstream code is claimed.

## Related public repository: Conly-Zy/Pojun

- Public source: https://github.com/chu0119/Pojun
- User-provided alias: https://github.com/Conly-Zy/Pojun
- Verified commit: `2230279b7e6eef1fdf2b008dda06664782e3b9c4`
- License: AGPL-3.0
- Reference copy: `licenses/REFERENCE-Conly-Zy-Pojun-AGPL-3.0.txt`
- Relationship to the unavailable CTF-Agent repository: UNKNOWN
- Code-copy status: no direct-copy evidence established

Pojun is documented as a related public research reference, not as a confirmed
source of bundled code. If future review proves actual code reuse, the affected
files and the project-level license must be re-evaluated.

## External tools installed but not vendored

Ghidra, JADX, Nuclei, httpx, Katana, Feroxbuster, Chisel, Ligolo-ng, NetExec,
Evil-WinRM, GEF, Pwndbg, Wireshark/tshark and other packages remain separate
third-party works. Their own licenses apply when users install them.
