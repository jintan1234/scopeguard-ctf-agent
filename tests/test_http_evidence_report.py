from __future__ import annotations

import http.server
import tempfile
import threading
import unittest
from pathlib import Path

from ctf_core.flagops import add_candidate, verify_flag
from ctf_core.http_client import perform_request
from ctf_core.report import write_report
from ctf_core.task import TaskManager
from ctf_core.util import read_json


FLAG = "CTF{local_round_trip}"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/flag")
            self.end_headers()
            return
        body = f"challenge result: {FLAG}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class HttpEvidenceReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.tasks = TaskManager(self.root)
        created = self.tasks.create(
            f"http://127.0.0.1:{self.server.server_port}/",
            "Find and verify the flag.",
            authorized=True,
        )
        self.task_id = created["task"]["task_id"]
        self.task_dir = Path(created["path"])

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temp.cleanup()

    def test_http_candidate_verify_and_report(self) -> None:
        response = perform_request(
            self.tasks,
            self.task_id,
            f"http://127.0.0.1:{self.server.server_port}/flag",
        )
        self.assertTrue(response["ok"], response)
        self.assertIn(FLAG, response["data"]["text"])
        evidence = response["artifacts"][0]["path"]
        candidate = add_candidate(
            self.tasks,
            self.task_id,
            FLAG,
            source="HTTP response",
            evidence_file=evidence,
        )
        self.assertTrue(candidate["ok"], candidate)
        verification = verify_flag(
            self.tasks,
            self.task_id,
            FLAG,
            expected_regex=r"CTF\{[^}]+\}",
            evidence_file=evidence,
        )
        self.assertTrue(verification["ok"], verification)
        self.assertEqual(verification["data"]["assurance"], "reproducible_evidence")
        report = write_report(
            self.tasks,
            self.task_id,
            challenge_type="web",
            summary="Fetched the local authorized endpoint and preserved the raw response.",
        )
        self.assertTrue(report["ok"], report)
        self.assertIn(FLAG, (self.task_dir / "report.md").read_text(encoding="utf-8"))
        result = read_json(self.task_dir / "result.json")
        self.assertTrue(result["success"])
        self.assertEqual(result["assurance"], "reproducible_evidence")

    def test_redirects_require_opt_in_and_scope(self) -> None:
        not_followed = perform_request(
            self.tasks,
            self.task_id,
            f"http://127.0.0.1:{self.server.server_port}/redirect",
            follow_redirects=False,
        )
        self.assertTrue(not_followed["ok"], not_followed)
        self.assertEqual(not_followed["data"]["status"], 302)
        followed = perform_request(
            self.tasks,
            self.task_id,
            f"http://127.0.0.1:{self.server.server_port}/redirect",
            follow_redirects=True,
        )
        self.assertTrue(followed["ok"], followed)
        self.assertEqual(followed["data"]["status"], 200)
        self.assertIn(FLAG, followed["data"]["text"])

    def test_out_of_scope_host_is_rejected(self) -> None:
        response = perform_request(
            self.tasks,
            self.task_id,
            "http://example.com/",
        )
        self.assertFalse(response["ok"])
        self.assertIn("outside the authorized scope", response["error"]["message"])


if __name__ == "__main__":
    unittest.main()
