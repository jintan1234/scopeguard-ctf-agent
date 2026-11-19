# Prompt templates

These prompts are short operator instructions for a Codex/MCP client. They are
designed to work with `AGENTS.md`, `skills/` and the `ctf-control` tool server.

Replace every `<PLACEHOLDER>` before use.

Prompts never grant authorization by themselves. The task must still be
created with `authorized=true` and an exact scope.

Recommended sequence:

0. `00-operator.zh-CN.md` for a complete Chinese control prompt
1. `01-start-authorized-task.md`
2. `02-recon-and-classify.md`
3. `03-bounded-exploit-loop.md`
4. `04-verify-and-report.md`
5. `05-stop-and-handoff.md`
