from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

from ctf_core.task import TaskManager


BROKER_PATH = Path(__file__).resolve().parents[1] / "mcp" / "docker-broker" / "broker.py"
spec = importlib.util.spec_from_file_location("ctf_docker_broker", BROKER_PATH)
assert spec and spec.loader
broker_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker_module)


class DockerBrokerTests(unittest.TestCase):
    def test_token_file_is_created_and_reused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "token"
            first = broker_module.ensure_token(path)
            second = broker_module.ensure_token(path)
            self.assertEqual(first, second)
            self.assertGreaterEqual(len(first), 32)

    def test_task_path_validation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tasks = TaskManager(root)
            created = tasks.create("http://127.0.0.1:3000/", "test", authorized=True)
            task_id = created["task"]["task_id"]
            resolved = broker_module.resolve_task_dir(root, task_id)
            self.assertEqual(resolved.name, task_id)
            with self.assertRaises(broker_module.BrokerError):
                broker_module.resolve_task_dir(root, "../escape")

    def test_container_spec_drops_host_access(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tasks = TaskManager(root)
            created = tasks.create("http://127.0.0.1:3000/", "test", authorized=True)
            task_id = created["task"]["task_id"]
            broker = broker_module.DockerBroker(root, dict(broker_module.PROFILE_DEFAULT_IMAGES))
            captured: list[list[str]] = []

            def fake_run(command: list[str], **kwargs: object) -> dict[str, object]:
                del kwargs
                captured.append(command)
                return {
                    "ok": True,
                    "exit_code": 0,
                    "duration_ms": 1,
                    "stdout": "a" * 64,
                    "stderr": "",
                    "truncated": False,
                }

            broker.run = fake_run  # type: ignore[method-assign]
            result = broker.create(task_id, "analysis")
            self.assertEqual(result["network"], "none")
            command = captured[0]
            self.assertIn("--network", command)
            self.assertEqual(command[command.index("--network") + 1], "none")
            self.assertIn("--cap-drop", command)
            self.assertEqual(command[command.index("--cap-drop") + 1], "ALL")
            self.assertIn("--read-only", command)
            self.assertIn("--security-opt", command)
            rendered = " ".join(command)
            self.assertNotIn("docker.sock", rendered)
            self.assertEqual(sum(1 for item in command if item == "--mount"), 4)
            task = broker_module.resolve_task_dir(root, task_id)
            mount_values = [
                command[index + 1]
                for index, item in enumerate(command)
                if item == "--mount"
            ]
            for mount in mount_values:
                source = Path(mount.split("source=", 1)[1].split(",target=", 1)[0]).resolve()
                self.assertTrue(source == task or task in source.parents, source)

    def test_all_declared_profiles_are_allowlisted(self) -> None:
        expected = {"analysis", "reverse", "pwn", "web", "crypto", "remote"}
        self.assertEqual(broker_module.SANDBOX_PROFILES, expected)
        self.assertTrue(expected.issubset(broker_module.PROFILE_DEFAULT_IMAGES))

    def test_optional_tool_runtime_is_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tasks = TaskManager(root)
            created = tasks.create("http://127.0.0.1:3000/", "test", authorized=True)
            task_id = created["task"]["task_id"]
            tool_runtime = root / "tool-runtime"
            tool_runtime.mkdir()
            broker = broker_module.DockerBroker(root, dict(broker_module.PROFILE_DEFAULT_IMAGES))
            captured: list[list[str]] = []

            def fake_run(command: list[str], **kwargs: object) -> dict[str, object]:
                del kwargs
                captured.append(command)
                return {
                    "ok": True,
                    "exit_code": 0,
                    "duration_ms": 1,
                    "stdout": "c" * 64,
                    "stderr": "",
                    "truncated": False,
                }

            broker.run = fake_run  # type: ignore[method-assign]
            broker.create(task_id, "analysis")
            command = captured[0]
            rendered = " ".join(command)
            self.assertIn(f"source={tool_runtime}", rendered)
            self.assertIn("target=/opt/ctf-tools,readonly", rendered)
            self.assertIn("CTF_TOOLS=/opt/ctf-tools", command)

    def test_lab_start_is_loopback_only_and_unmounted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            broker = broker_module.DockerBroker(root, dict(broker_module.PROFILE_DEFAULT_IMAGES))
            calls: list[list[str]] = []

            def fake_run(command: list[str], **kwargs: object) -> dict[str, object]:
                del kwargs
                calls.append(command)
                if "inspect" in command:
                    return {
                        "ok": False,
                        "exit_code": 1,
                        "duration_ms": 1,
                        "stdout": "",
                        "stderr": "missing",
                        "truncated": False,
                    }
                return {
                    "ok": True,
                    "exit_code": 0,
                    "duration_ms": 1,
                    "stdout": "b" * 64,
                    "stderr": "",
                    "truncated": False,
                }

            broker.run = fake_run  # type: ignore[method-assign]
            result = broker.lab_start("juice-shop", 3000)
            self.assertEqual(result["url"], "http://127.0.0.1:3000")
            command = calls[-1]
            rendered = " ".join(command)
            self.assertIn("127.0.0.1:3000:3000", command)
            self.assertIn("--cap-drop", command)
            self.assertNotIn("docker.sock", rendered)
            self.assertFalse(any("host" in item and "target" in item for item in command))
            with self.assertRaises(broker_module.BrokerError):
                broker.lab_start("arbitrary-image", 3000)


if __name__ == "__main__":
    unittest.main()
