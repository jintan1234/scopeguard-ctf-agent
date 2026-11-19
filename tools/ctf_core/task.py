from __future__ import annotations

import hashlib
import json
import secrets
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .evidence import EvidenceLedger
from .models import utc_now
from .scope import build_scope
from .util import (
    PolicyError,
    atomic_write_json,
    exclusive_lock,
    project_root,
    read_json,
    safe_copy_file,
)


DEFAULT_LIMITS = {
    "max_tool_calls": 200,
    "max_seconds": 1800,
    "max_consecutive_no_progress": 12,
    "max_retries_per_action": 2,
    "max_output_bytes": 65536,
}


def load_budget_limits(root: Path) -> dict[str, int]:
    limits = dict(DEFAULT_LIMITS)
    path = root / "config" / "budgets.toml"
    if not path.is_file():
        return limits
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return limits
    task = data.get("task", {})
    output = data.get("output", {})
    for source_key, target_key in (
        ("max_wall_seconds", "max_seconds"),
        ("max_tool_calls", "max_tool_calls"),
        ("max_consecutive_no_progress", "max_consecutive_no_progress"),
        ("max_retries_per_action", "max_retries_per_action"),
    ):
        if source_key in task:
            limits[target_key] = max(0, int(task[source_key]))
    if "max_inline_bytes" in output:
        limits["max_output_bytes"] = max(0, int(output["max_inline_bytes"]))
    return limits


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


class TaskManager:
    def __init__(self, root: Path | None = None):
        self.root = (root or project_root()).resolve()
        self.current_root = self.root / "challenges" / "current"
        self.current_root.mkdir(parents=True, exist_ok=True)

    def create(
        self,
        target_url: str,
        instruction: str,
        *,
        authorized: bool,
        allowed_hosts: list[str] | None = None,
        allowed_ports: list[int] | None = None,
        allowed_schemes: list[str] | None = None,
        allowed_redirect_hosts: list[str] | None = None,
        attachments: list[str] | None = None,
        max_attachment_bytes: int = 256 * 1024 * 1024,
    ) -> dict[str, Any]:
        if not instruction.strip():
            raise PolicyError("instruction must not be empty")
        scope = build_scope(
            target_url,
            authorized=authorized,
            allowed_hosts=allowed_hosts,
            allowed_ports=allowed_ports,
            allowed_schemes=allowed_schemes,
            allowed_redirect_hosts=allowed_redirect_hosts,
        )
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        task_id = f"{stamp}-{secrets.token_hex(3)}"
        task_dir = self.current_root / task_id
        task_dir.mkdir(parents=True, exist_ok=False)
        for name in ("input", "artifacts", "exploit", "evidence"):
            (task_dir / name).mkdir()
        attachment_records: list[dict[str, Any]] = []
        for raw_path in attachments or []:
            source = Path(raw_path)
            destination = safe_copy_file(source, task_dir / "input", max_attachment_bytes)
            attachment_records.append(
                {
                    "original": str(source),
                    "local": destination.relative_to(task_dir).as_posix(),
                    "size": destination.stat().st_size,
                }
            )
        limits = load_budget_limits(self.root)
        task = {
            "task_id": task_id,
            "created_at": utc_now(),
            "target_url": target_url,
            "instruction": instruction,
            "authorized": True,
            "attachments": attachment_records,
            "limits": limits,
        }
        state = {
            "task_id": task_id,
            "status": "SCOPED",
            "created_at": task["created_at"],
            "updated_at": task["created_at"],
            "tool_calls": 0,
            "consecutive_no_progress": 0,
            "candidate_flags": [],
            "verified_flags": [],
            "budget_exhausted_reason": None,
            "action_counts": {},
            "workflow": {
                "phase": "SCOPED",
                "challenge_type": "unknown",
                "primary_hypothesis": "",
                "fallback_hypothesis": "",
                "next_actions": [],
                "unresolved": [],
            },
        }
        atomic_write_json(task_dir / "task.json", task)
        atomic_write_json(task_dir / "scope.json", scope)
        atomic_write_json(
            self.current_root / "active-scope.json",
            {"task_id": task_id, **scope},
        )
        atomic_write_json(task_dir / "state.json", state)
        (task_dir / "notes.md").write_text(
            f"# CTF Task {task_id}\n\n## Instruction\n\n{instruction}\n",
            encoding="utf-8",
        )
        EvidenceLedger(task_dir).event(
            "task_created",
            target_url=target_url,
            instruction=instruction,
            allowed_hosts=scope["allowed_hosts"],
            allowed_ports=scope["allowed_ports"],
        )
        return {"task": task, "scope": scope, "state": state, "path": str(task_dir)}

    def get_dir(self, task_id: str) -> Path:
        if not task_id or any(char not in "0123456789abcdef-" for char in task_id.lower()):
            raise PolicyError("invalid task id")
        path = (self.current_root / task_id).resolve()
        if path.parent != self.current_root.resolve() or not path.is_dir():
            raise FileNotFoundError(f"task not found: {task_id}")
        return path

    def get(self, task_id: str) -> dict[str, Any]:
        task_dir = self.get_dir(task_id)
        task = read_json(task_dir / "task.json")
        state = read_json(task_dir / "state.json")
        return {
            "task": task,
            "scope": read_json(task_dir / "scope.json"),
            "state": state,
            "budget": self.budget_snapshot(task, state),
            "path": str(task_dir),
        }

    def update_state(self, task_id: str, **changes: Any) -> dict[str, Any]:
        task_dir = self.get_dir(task_id)
        state = read_json(task_dir / "state.json")
        state.update(changes)
        state["updated_at"] = utc_now()
        atomic_write_json(task_dir / "state.json", state)
        return state

    def budget_snapshot(self, task: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
        limits = {**DEFAULT_LIMITS, **task.get("limits", {})}
        created = _parse_timestamp(str(task["created_at"]))
        elapsed = max(0.0, (datetime.now(timezone.utc) - created).total_seconds())
        max_seconds = int(limits["max_seconds"])
        max_calls = int(limits["max_tool_calls"])
        calls = int(state.get("tool_calls", 0))
        no_progress = int(state.get("consecutive_no_progress", 0))
        return {
            "max_tool_calls": max_calls,
            "tool_calls_used": calls,
            "tool_calls_remaining": max(0, max_calls - calls),
            "max_seconds": max_seconds,
            "elapsed_seconds": round(elapsed, 3),
            "seconds_remaining": max(0, round(max_seconds - elapsed, 3)),
            "max_consecutive_no_progress": int(limits["max_consecutive_no_progress"]),
            "consecutive_no_progress": no_progress,
            "max_retries_per_action": int(limits["max_retries_per_action"]),
            "exhausted_reason": state.get("budget_exhausted_reason"),
        }

    @staticmethod
    def action_signature(tool_name: str, arguments: dict[str, Any]) -> str:
        payload = json.dumps(
            {"tool": tool_name, "arguments": arguments},
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]

    def begin_tool_call(
        self,
        task_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        exempt: bool = False,
    ) -> dict[str, Any]:
        task_dir = self.get_dir(task_id)
        with exclusive_lock(task_dir / "state.lock"):
            return self._begin_tool_call(
                task_dir,
                task_id,
                tool_name,
                arguments,
                exempt=exempt,
            )

    def _begin_tool_call(
        self,
        task_dir: Path,
        task_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        exempt: bool,
    ) -> dict[str, Any]:
        state = read_json(task_dir / "state.json")
        task = read_json(task_dir / "task.json")
        limits = {**DEFAULT_LIMITS, **task.get("limits", {})}
        if exempt:
            return {"allowed": True, "exempt": True, "budget": self.budget_snapshot(task, state)}

        status = str(state.get("status", "SCOPED")).upper()
        if status in {"BLOCKED", "BUDGETED"}:
            return {
                "allowed": False,
                "code": "BUDGET_EXHAUSTED" if status == "BUDGETED" else "TASK_STOPPED",
                "message": state.get("budget_exhausted_reason") or f"task status is {status}",
                "budget": self.budget_snapshot(task, state),
            }
        if status == "VERIFIED" and tool_name not in {
            "ctf_task_status",
            "ctf_task_update",
            "ctf_evidence_record",
            "ctf_register_artifact",
            "ctf_report_write",
        }:
            return {
                "allowed": False,
                "code": "TASK_VERIFIED",
                "message": "A flag is verified; only evidence/report actions are allowed.",
                "budget": self.budget_snapshot(task, state),
            }
        if status == "REPORTED":
            return {
                "allowed": False,
                "code": "TASK_REPORTED",
                "message": "The task is already reported.",
                "budget": self.budget_snapshot(task, state),
            }

        snapshot = self.budget_snapshot(task, state)
        if snapshot["elapsed_seconds"] >= snapshot["max_seconds"]:
            state["status"] = "BUDGETED"
            state["budget_exhausted_reason"] = "max_wall_seconds reached"
        elif snapshot["tool_calls_used"] >= snapshot["max_tool_calls"]:
            state["status"] = "BUDGETED"
            state["budget_exhausted_reason"] = "max_tool_calls reached"
        elif snapshot["consecutive_no_progress"] >= snapshot["max_consecutive_no_progress"]:
            state["status"] = "BUDGETED"
            state["budget_exhausted_reason"] = "max_consecutive_no_progress reached"
        if state.get("budget_exhausted_reason"):
            state["status"] = "BUDGETED"
            state["updated_at"] = utc_now()
            atomic_write_json(task_dir / "state.json", state)
            return {
                "allowed": False,
                "code": "BUDGET_EXHAUSTED",
                "message": state["budget_exhausted_reason"],
                "budget": self.budget_snapshot(task, state),
            }

        signature = self.action_signature(tool_name, arguments)
        action_counts = state.setdefault("action_counts", {})
        attempts = int(action_counts.get(signature, 0)) + 1
        allowed_attempts = int(limits["max_retries_per_action"]) + 1
        if attempts > allowed_attempts:
            return {
                "allowed": False,
                "code": "ACTION_RETRY_LIMIT",
                "message": (
                    f"identical action retry limit reached ({allowed_attempts} attempts); "
                    "change the hypothesis or tool"
                ),
                "budget": self.budget_snapshot(task, state),
            }

        action_counts[signature] = attempts
        state["tool_calls"] = int(state.get("tool_calls", 0)) + 1
        state["last_tool"] = tool_name
        state["last_action_signature"] = signature
        state["updated_at"] = utc_now()
        atomic_write_json(task_dir / "state.json", state)
        return {"allowed": True, "exempt": False, "budget": self.budget_snapshot(task, state)}

    def finish_tool_call(
        self,
        task_id: str,
        tool_name: str,
        *,
        ok: bool,
    ) -> dict[str, Any]:
        task_dir = self.get_dir(task_id)
        with exclusive_lock(task_dir / "state.lock"):
            return self._finish_tool_call(task_dir, tool_name, ok=ok)

    def _finish_tool_call(
        self,
        task_dir: Path,
        tool_name: str,
        *,
        ok: bool,
    ) -> dict[str, Any]:
        state = read_json(task_dir / "state.json")
        task = read_json(task_dir / "task.json")
        limits = {**DEFAULT_LIMITS, **task.get("limits", {})}
        if ok:
            state["consecutive_no_progress"] = 0
            state["last_progress_at"] = utc_now()
        else:
            state["consecutive_no_progress"] = int(state.get("consecutive_no_progress", 0)) + 1
            if (
                state["consecutive_no_progress"]
                >= int(limits["max_consecutive_no_progress"])
                and state.get("status") not in {"VERIFIED", "REPORTED"}
            ):
                state["status"] = "BUDGETED"
                state["budget_exhausted_reason"] = "max_consecutive_no_progress reached"
        state["updated_at"] = utc_now()
        atomic_write_json(task_dir / "state.json", state)
        return state

    def update_workflow(
        self,
        task_id: str,
        *,
        phase: str | None = None,
        challenge_type: str | None = None,
        primary_hypothesis: str | None = None,
        fallback_hypothesis: str | None = None,
        next_actions: list[str] | None = None,
        unresolved: list[str] | None = None,
        progress_note: str | None = None,
    ) -> dict[str, Any]:
        task_dir = self.get_dir(task_id)
        state = read_json(task_dir / "state.json")
        workflow = state.setdefault("workflow", {})
        changes: dict[str, Any] = {}
        if phase is not None:
            workflow["phase"] = phase
            changes["phase"] = phase
            if phase in {"SCOPED", "RECON", "CLASSIFIED", "EXPLOITING", "VERIFIED", "REPORTED", "BLOCKED"}:
                state["status"] = phase
        if challenge_type is not None:
            workflow["challenge_type"] = challenge_type
            changes["challenge_type"] = challenge_type
        if primary_hypothesis is not None:
            workflow["primary_hypothesis"] = primary_hypothesis
            changes["primary_hypothesis"] = primary_hypothesis
        if fallback_hypothesis is not None:
            workflow["fallback_hypothesis"] = fallback_hypothesis
            changes["fallback_hypothesis"] = fallback_hypothesis
        if next_actions is not None:
            workflow["next_actions"] = [str(item)[:1000] for item in next_actions[:20]]
            changes["next_actions"] = workflow["next_actions"]
        if unresolved is not None:
            workflow["unresolved"] = [str(item)[:1000] for item in unresolved[:20]]
            changes["unresolved"] = workflow["unresolved"]
        if progress_note is not None:
            workflow["progress_note"] = str(progress_note)[:4000]
            changes["progress_note"] = workflow["progress_note"]
            state["consecutive_no_progress"] = 0
            state["last_progress_at"] = utc_now()
        state["updated_at"] = utc_now()
        atomic_write_json(task_dir / "state.json", state)
        EvidenceLedger(task_dir).event("workflow_update", **changes)
        return self.get(task_id)
