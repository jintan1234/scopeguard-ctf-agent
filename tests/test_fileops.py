from __future__ import annotations

import base64
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from ctf_core.fileops import analyze_pcap, find_tshark, inspect_file, inspect_image
from ctf_core.task import TaskManager


PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Zl1sAAAAASUVORK5CYII="
)


class FileOperationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.tasks = TaskManager(self.root)
        created = self.tasks.create(
            "http://127.0.0.1:3000/",
            "Inspect the supplied challenge files.",
            authorized=True,
        )
        self.task_id = created["task"]["task_id"]
        self.task_dir = Path(created["path"])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_inspect_zip(self) -> None:
        archive_path = self.task_dir / "input" / "sample.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("hidden/flag.txt", "CTF{zip_member}")
        result = inspect_file(self.tasks, self.task_id, "input/sample.zip")
        self.assertTrue(result["ok"], result)
        self.assertIn("zip", result["data"]["magic"])
        self.assertEqual(result["data"]["zip_members"][0]["name"], "hidden/flag.txt")
        self.assertIn("CTF{zip_member}", " ".join(result["data"]["strings"]))

    def test_inspect_png_and_reject_escape(self) -> None:
        image_path = self.task_dir / "input" / "pixel.png"
        image_path.write_bytes(PNG_1X1)
        result = inspect_image(self.tasks, self.task_id, "input/pixel.png")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["data"]["format"], "png")
        escape = inspect_file(self.tasks, self.task_id, "../../outside.bin")
        self.assertFalse(escape["ok"])
        self.assertEqual(escape["error"]["code"], "FILE_INSPECT_FAILED")

    @unittest.skipUnless(find_tshark(), "tshark is not installed")
    def test_empty_pcap_protocol_hierarchy(self) -> None:
        pcap = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        path = self.task_dir / "input" / "empty.pcap"
        path.write_bytes(pcap)
        result = analyze_pcap(self.tasks, self.task_id, "input/empty.pcap", timeout_seconds=15)
        self.assertTrue(result["ok"], result)
        self.assertIn("Protocol Hierarchy Statistics", result["data"]["protocol_hierarchy"])


if __name__ == "__main__":
    unittest.main()
