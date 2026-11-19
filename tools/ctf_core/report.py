from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ToolError, envelope, utc_now
from .task import TaskManager
from .util import atomic_write_json, read_json


def _read_events(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def write_report(
    task_manager: TaskManager,
    task_id: str,
    *,
    challenge_type: str = "unknown",
    summary: str = "",
    unresolved: list[str] | None = None,
) -> dict[str, Any]:
    try:
        task_dir = task_manager.get_dir(task_id)
        task = read_json(task_dir / "task.json")
        state = read_json(task_dir / "state.json")
        events = _read_events(task_dir / "evidence" / "events.jsonl")
        commands = [event for event in events if event.get("type") == "command"]
        artifacts = [event for event in events if event.get("type") == "artifact"]
        verified_flags = state.get("verified_flags", [])
        candidates = state.get("candidate_flags", [])
        workflow = state.get("workflow", {})
        budget = task_manager.budget_snapshot(task, state)
        assurance = (
            verified_flags[-1]["assurance"] if verified_flags else "unverified"
        )
        result = {
            "task_id": task_id,
            "generated_at": utc_now(),
            "target": task.get("target_url"),
            "instruction": task.get("instruction"),
            "challenge_type": challenge_type,
            "success": bool(verified_flags),
            "flag": verified_flags[-1]["value"] if verified_flags else None,
            "assurance": assurance,
            "candidate_flags": candidates,
            "tool_calls": state.get("tool_calls", 0),
            "workflow": workflow,
            "budget": budget,
            "commands": commands,
            "artifacts": artifacts,
            "summary": summary,
            "unresolved": unresolved or [],
        }
        atomic_write_json(task_dir / "result.json", result)
        lines = [
            f"# CTF Report: {task_id}",
            "",
            f"- Target: `{task.get('target_url')}`",
            f"- Challenge type: `{challenge_type}`",
            f"- Generated: `{result['generated_at']}`",
            f"- Tool calls: `{result['tool_calls']}`",
            f"- Workflow phase: `{workflow.get('phase', 'unknown')}`",
            f"- Budget stop reason: `{budget.get('exhausted_reason') or 'none'}`",
            "",
            "## Flag",
            "",
        ]
        if verified_flags:
            flag = verified_flags[-1]
            lines.extend(
                [
                    f"`{flag['value']}`",
                    "",
                    f"Assurance: `{flag['assurance']}`",
                    f"Evidence: `{flag.get('evidence_file') or 'format-only'}`",
                ]
            )
        else:
            lines.append("No verified flag.")
        lines.extend(["", "## Instruction", "", task.get("instruction", "")])
        lines.extend(
            [
                "",
                "## Reasoning",
                "",
                f"- Primary hypothesis: {workflow.get('primary_hypothesis') or 'Not recorded.'}",
                f"- Fallback hypothesis: {workflow.get('fallback_hypothesis') or 'Not recorded.'}",
                f"- Progress note: {workflow.get('progress_note') or 'Not recorded.'}",
            ]
        )
        next_actions = workflow.get("next_actions") or []
        lines.extend(["", "### Next Actions", ""])
        if next_actions:
            lines.extend(f"- {item}" for item in next_actions)
        else:
            lines.append("None.")
        lines.extend(["", "## Summary", "", summary or "No summary supplied."])
        lines.extend(["", "## Candidate Flags", ""])
        if candidates:
            for item in candidates:
                lines.append(
                    f"- `{item.get('value')}` — assurance `{item.get('assurance', 'unverified')}`, "
                    f"source `{item.get('source', '')}`"
                )
        else:
            lines.append("None.")
        lines.extend(["", "## Commands", ""])
        if commands:
            for index, item in enumerate(commands, 1):
                command = item.get("command", [])
                rendered = " ".join(str(part) for part in command)
                lines.append(
                    f"{index}. `exit={item.get('exit_code')}` `{rendered}`"
                )
                if item.get("stderr_summary"):
                    lines.append(f"   - stderr: `{item['stderr_summary'][:300]}`")
        else:
            lines.append("No commands recorded.")
        lines.extend(["", "## Artifacts", ""])
        if artifacts:
            for item in artifacts:
                lines.append(f"- `{item.get('path')}` — sha256 `{item.get('sha256')}`")
        else:
            lines.append("No artifacts recorded.")
        lines.extend(["", "## Unresolved", ""])
        if unresolved:
            lines.extend(f"- {item}" for item in unresolved)
        else:
            lines.append("None recorded.")
        (task_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        task_manager.update_state(task_id, status="REPORTED")
        return envelope(
            "ctf_report_write",
            ok=True,
            task_id=task_id,
            data=result,
            artifacts=[
                {"path": "report.md", "kind": "text/markdown"},
                {"path": "result.json", "kind": "application/json"},
            ],
        )
    except Exception as exc:
        return envelope(
            "ctf_report_write",
            ok=False,
            task_id=task_id,
            exit_code=1,
            error=ToolError("REPORT_WRITE_FAILED", str(exc)),
        )
