from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class McpProtocolTests(unittest.TestCase):
    def test_initialize_list_and_call(self) -> None:
        project = Path(__file__).resolve().parents[1]
        python = os.environ.get("CTF_PYTHON", sys.executable)
        with tempfile.TemporaryDirectory() as raw:
            env = os.environ.copy()
            env["PYTHONPATH"] = str(project / "tools")
            env.pop("CTF_AGENT_ROOT", None)
            messages = [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
                },
                {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "ctf_doctor", "arguments": {}},
                },
            ]
            payload = "".join(
                json.dumps(message, separators=(",", ":")) + "\n" for message in messages
            )
            completed = subprocess.run(
                [python, "-m", "ctf_core.mcp_server"],
                input=payload,
                text=True,
                capture_output=True,
                timeout=20,
                env=env,
                cwd=project,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            responses = [
                json.loads(line)
                for line in completed.stdout.splitlines()
                if line.strip()
            ]
            by_id = {item.get("id"): item for item in responses}
            self.assertEqual(
                by_id[1]["result"]["serverInfo"]["name"],
                "ctf-control",
            )
            tool_names = {tool["name"] for tool in by_id[2]["result"]["tools"]}
            self.assertTrue(
                {
                    "ctf_task_create",
                    "ctf_task_update",
                    "ctf_http_request",
                    "ctf_flag_scan",
                    "ctf_flag_submit",
                    "ctf_evidence_record",
                    "ctf_register_artifact",
                    "ctf_remote_exec",
                    "ctf_remote_http",
                }.issubset(tool_names)
            )
            doctor = by_id[3]["result"]["structuredContent"]
            self.assertTrue(doctor["ok"])
            self.assertTrue(Path(raw).is_dir())


if __name__ == "__main__":
    unittest.main()
