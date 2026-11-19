from __future__ import annotations

import http.server
import base64
import json
import tempfile
import threading
import unittest
from pathlib import Path

from ctf_core.flagops import validate_juice_shop_admin
from ctf_core.task import TaskManager


class _AdminHandler(http.server.BaseHTTPRequestHandler):
    token = ""

    def do_GET(self) -> None:
        if self.headers.get("Authorization") != f"Bearer {self.token}":
            self.send_response(401)
            self.end_headers()
            return
        if self.path == "/rest/user/whoami":
            payload: dict = {"user": {}}
        elif self.path.startswith("/api/Challenges/"):
            payload = {
                "status": "success",
                "data": [{"name": "Login Admin", "solved": True}],
            }
        else:
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class LocalValidatorTests(unittest.TestCase):
    def test_juice_shop_admin_validator(self) -> None:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _AdminHandler)
        claims = {
            "data": {"id": 1, "email": "admin@juice-sh.op", "role": "admin"},
            "bid": 1,
        }
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        token = f"header.{payload}.signature"
        _AdminHandler.token = token
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as raw:
                tasks = TaskManager(Path(raw))
                created = tasks.create(
                    f"http://127.0.0.1:{server.server_port}/",
                    "Login Admin local test",
                    authorized=True,
                )
                result = validate_juice_shop_admin(
                    tasks,
                    created["task"]["task_id"],
                    token,
                )
                self.assertTrue(result["ok"], result)
                self.assertEqual(result["data"]["assurance"], "local_validator_verified")
                self.assertEqual(result["data"]["value"], "FLAG{JUICE_SHOP_LOGIN_ADMIN}")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
