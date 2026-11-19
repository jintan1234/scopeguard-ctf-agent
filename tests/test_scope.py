from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ctf_core.scope import ScopePolicy, build_scope
from ctf_core.task import TaskManager
from ctf_core.util import PolicyError, resolve_within


class ScopeTests(unittest.TestCase):
    def test_authorization_is_required(self) -> None:
        with self.assertRaises(PolicyError):
            build_scope("http://127.0.0.1:3000", authorized=False)

    def test_scope_is_exact_host_and_port(self) -> None:
        scope = ScopePolicy(
            authorized=True,
            target_url="http://127.0.0.1:3000/",
            allowed_hosts=("127.0.0.1",),
            allowed_ports=(3000,),
            allowed_schemes=("http",),
        )
        checked = scope.validate_url("http://127.0.0.1:3000/api")
        self.assertEqual(checked["host"], "127.0.0.1")
        with self.assertRaises(PolicyError):
            scope.validate_url("http://127.0.0.1:3001/api")
        with self.assertRaises(PolicyError):
            scope.validate_url("https://127.0.0.1:3000/api")
        with self.assertRaises(PolicyError):
            scope.validate_url("http://example.com:3000/api")

    def test_metadata_address_is_blocked(self) -> None:
        scope = ScopePolicy(
            authorized=True,
            target_url="http://169.254.169.254/",
            allowed_hosts=("169.254.169.254",),
            allowed_ports=(80,),
            allowed_schemes=("http",),
        )
        with self.assertRaises(PolicyError):
            scope.validate_url("http://169.254.169.254/latest/meta-data")

    def test_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "inside").mkdir()
            with self.assertRaises(PolicyError):
                resolve_within(root / "inside", "../../outside.txt")

    def test_task_manifest_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            manager = TaskManager(Path(raw))
            created = manager.create(
                "http://127.0.0.1:3000/",
                "Inspect only this lab.",
                authorized=True,
            )
            task_id = created["task"]["task_id"]
            loaded = manager.get(task_id)
            self.assertEqual(loaded["scope"]["allowed_hosts"], ["127.0.0.1"])
            self.assertEqual(loaded["scope"]["allowed_ports"], [3000])
            self.assertTrue((Path(loaded["path"]) / "evidence" / "events.jsonl").is_file())


if __name__ == "__main__":
    unittest.main()
