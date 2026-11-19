from __future__ import annotations

import http.server
import json
import tempfile
import threading
import unittest
from pathlib import Path

from ctf_core.evidence_ops import record_action
from ctf_core.flagops import scan_flags, submit_flag
from ctf_core.mcp_tools import ToolRegistry
from ctf_core.remote_ops import build_remote_http_command, execute_remote_http, execute_ssh
from ctf_core.task import TaskManager
from ctf_core.util import atomic_write_json, read_json


def _write_budgets(root: Path, **values: int) -> None:
    defaults = {
        "max_wall_seconds": 1800,
        "max_tool_calls": 200,
        "max_consecutive_no_progress": 12,
        "max_retries_per_action": 2,
    }
    defaults.update(values)
    path = root / "config" / "budgets.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "[task]\n"
        + "\n".join(f"{key} = {value}" for key, value in defaults.items())
        + "\n[output]\nmax_inline_bytes = 65536\n",
        encoding="utf-8",
    )


class _SubmitHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        accepted = payload.get("flag") == "CTF{platform_accepted}"
        body = json.dumps({"accepted": accepted}).encode()
        self.send_response(200 if accepted else 400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class AgentControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _task(self, **create_args: object) -> tuple[TaskManager, str, Path]:
        _write_budgets(self.root)
        tasks = TaskManager(self.root)
        created = tasks.create(
            str(create_args.pop("target_url", "http://127.0.0.1:3000/")),
            "Control-loop test.",
            authorized=True,
            **create_args,
        )
        return tasks, created["task"]["task_id"], Path(created["path"])

    def test_tool_budget_blocks_before_execution(self) -> None:
        _write_budgets(self.root, max_tool_calls=1)
        registry = ToolRegistry(self.root)
        created = registry.task_create(
            {
                "target_url": "http://127.0.0.1:3000/",
                "instruction": "Budget test.",
                "authorized": True,
            }
        )
        task_id = created["task_id"]
        task_dir = registry.tasks.get_dir(task_id)
        (task_dir / "input" / "sample.txt").write_text("CTF{budget}", encoding="utf-8")
        first = registry.call(
            "ctf_file_inspect",
            {"task_id": task_id, "file": "input/sample.txt"},
        )
        second = registry.call(
            "ctf_file_inspect",
            {"task_id": task_id, "file": "input/sample.txt", "max_strings": 1},
        )
        self.assertTrue(first["ok"], first)
        self.assertFalse(second["ok"], second)
        self.assertEqual(second["error"]["code"], "BUDGET_EXHAUSTED")
        state = read_json(task_dir / "state.json")
        self.assertEqual(state["tool_calls"], 1)
        self.assertEqual(state["status"], "BUDGETED")

    def test_identical_action_retry_limit(self) -> None:
        _write_budgets(
            self.root,
            max_tool_calls=20,
            max_retries_per_action=2,
            max_consecutive_no_progress=20,
        )
        registry = ToolRegistry(self.root)
        created = registry.task_create(
            {
                "target_url": "http://127.0.0.1:3000/",
                "instruction": "Retry test.",
                "authorized": True,
            }
        )
        task_id = created["task_id"]
        args = {"task_id": task_id, "file": "input/missing.txt"}
        for _ in range(3):
            result = registry.call("ctf_file_inspect", dict(args))
            self.assertFalse(result["ok"], result)
            self.assertNotEqual(result["error"]["code"], "ACTION_RETRY_LIMIT")
        blocked = registry.call("ctf_file_inspect", dict(args))
        self.assertFalse(blocked["ok"], blocked)
        self.assertEqual(blocked["error"]["code"], "ACTION_RETRY_LIMIT")

    def test_no_progress_budget_and_wall_clock(self) -> None:
        _write_budgets(
            self.root,
            max_tool_calls=20,
            max_retries_per_action=20,
            max_consecutive_no_progress=2,
        )
        registry = ToolRegistry(self.root)
        created = registry.task_create(
            {
                "target_url": "http://127.0.0.1:3000/",
                "instruction": "No-progress test.",
                "authorized": True,
            }
        )
        task_id = created["task_id"]
        registry.call("ctf_file_inspect", {"task_id": task_id, "file": "input/a"})
        registry.call("ctf_file_inspect", {"task_id": task_id, "file": "input/b"})
        blocked = registry.call("ctf_file_inspect", {"task_id": task_id, "file": "input/c"})
        self.assertFalse(blocked["ok"], blocked)
        self.assertEqual(blocked["error"]["code"], "BUDGET_EXHAUSTED")

        tasks, wall_task_id, wall_dir = self._task()
        task_path = wall_dir / "task.json"
        task = read_json(task_path)
        task["created_at"] = "2000-01-01T00:00:00+00:00"
        atomic_write_json(task_path, task)
        decision = tasks.begin_tool_call(
            wall_task_id,
            "ctf_file_inspect",
            {"task_id": wall_task_id, "file": "input/a"},
        )
        self.assertFalse(decision["allowed"], decision)
        self.assertEqual(decision["code"], "BUDGET_EXHAUSTED")

    def test_workflow_and_evidence_recording(self) -> None:
        tasks, task_id, task_dir = self._task()
        result = tasks.update_workflow(
            task_id,
            phase="EXPLOITING",
            challenge_type="web",
            primary_hypothesis="SQL injection",
            fallback_hypothesis="Access control",
            next_actions=["test id parameter"],
            progress_note="Login endpoint identified.",
        )
        self.assertEqual(result["state"]["workflow"]["phase"], "EXPLOITING")
        artifact = task_dir / "artifacts" / "proof.txt"
        artifact.write_text("CTF{recorded}", encoding="utf-8")
        recorded = record_action(
            tasks,
            task_id,
            description="Recorded browser-console command",
            command=["node", "probe.js"],
            exit_code=0,
            stdout="CTF{recorded}",
            artifact_files=["artifacts/proof.txt"],
        )
        self.assertTrue(recorded["ok"], recorded)
        commands = (task_dir / "evidence" / "commands.jsonl").read_text(encoding="utf-8")
        events = (task_dir / "evidence" / "events.jsonl").read_text(encoding="utf-8")
        self.assertIn("node", commands)
        self.assertIn("proof.txt", events)
        self.assertIn("agent_action", events)

    def test_flag_scan_registers_candidates(self) -> None:
        tasks, task_id, task_dir = self._task()
        evidence = task_dir / "evidence" / "response.txt"
        evidence.write_text(
            "first CTF{scan_me}; hash deadbeefdeadbeefdeadbeefdeadbeef",
            encoding="utf-8",
        )
        result = scan_flags(tasks, task_id, evidence_file="evidence/response.txt")
        self.assertTrue(result["ok"], result)
        values = {item["value"] for item in result["data"]["candidates"]}
        self.assertIn("CTF{scan_me}", values)
        self.assertIn("deadbeefdeadbeefdeadbeefdeadbeef", values)
        state = read_json(task_dir / "state.json")
        self.assertEqual(len(state["candidate_flags"]), 2)

    def test_platform_submission_marks_verified(self) -> None:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SubmitHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            tasks, task_id, task_dir = self._task(
                target_url=f"http://127.0.0.1:{server.server_port}/",
            )
            result = submit_flag(
                tasks,
                task_id,
                candidate="CTF{platform_accepted}",
                submission_url=f"http://127.0.0.1:{server.server_port}/submit",
                expected_success_regex=r'"accepted"\s*:\s*true',
            )
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["data"]["assurance"], "platform_verified")
            state = read_json(task_dir / "state.json")
            self.assertEqual(state["status"], "VERIFIED")
            self.assertEqual(state["verified_flags"][-1]["assurance"], "platform_verified")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_remote_exec_requires_scope_and_destructive_confirmation(self) -> None:
        tasks, task_id, _ = self._task(
            target_url="http://127.0.0.1:3000/",
            allowed_hosts=["127.0.0.1"],
            allowed_ports=[3000, 22],
        )
        result = execute_ssh(
            tasks,
            task_id,
            host="127.0.0.1",
            username="root",
            command="rm -rf /tmp/should-not-run",
            port=22,
        )
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["error"]["code"], "REMOTE_EXEC_FAILED")
        self.assertIn("destructive", result["error"]["message"])

    def test_remote_http_is_fixed_and_scope_checked(self) -> None:
        command = build_remote_http_command(
            url="http://127.0.0.1:3000/item?id=1",
            method="POST",
            headers={"Content-Type": "application/json"},
            body='{"id":1}',
            timeout_seconds=10,
        )
        self.assertIn("curl", command)
        self.assertIn("--data-binary", command)
        self.assertIn("http://127.0.0.1:3000/item?id=1", command)

        tasks, task_id, _ = self._task(
            target_url="http://127.0.0.1:3000/",
            allowed_hosts=["127.0.0.1"],
            allowed_ports=[22, 3000],
        )
        rejected = execute_remote_http(
            tasks,
            task_id,
            ssh_host="127.0.0.1",
            ssh_username="root",
            ssh_port=22,
            target_url="http://127.0.0.1:3001/outside",
        )
        self.assertFalse(rejected["ok"], rejected)
        self.assertEqual(rejected["error"]["code"], "REMOTE_HTTP_FAILED")
        self.assertIn("outside the authorized scope", rejected["error"]["message"])


if __name__ == "__main__":
    unittest.main()
