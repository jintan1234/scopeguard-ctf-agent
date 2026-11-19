from __future__ import annotations

import base64
import py_compile
import tempfile
import unittest
import zipfile
from pathlib import Path

from ctf_core.analysis_ops import archive_inspect, reverse_static
from ctf_core.crypto_ops import auto_decode
from ctf_core.task import TaskManager


class AdvancedAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.tasks = TaskManager(Path(self.temp.name))
        created = self.tasks.create(
            "http://127.0.0.1:3000/",
            "Analyze supplied challenge files.",
            authorized=True,
        )
        self.task_id = created["task"]["task_id"]
        self.task_dir = Path(created["path"])

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_base64_auto_decode_finds_flag(self) -> None:
        path = self.task_dir / "input" / "encoded.txt"
        path.write_text(base64.b64encode(b"CTF{decoded_chain}").decode(), encoding="ascii")
        result = auto_decode(self.tasks, self.task_id, "input/encoded.txt")
        self.assertTrue(result["ok"], result)
        texts = [candidate["text_preview"] for candidate in result["data"]["candidates"]]
        self.assertTrue(any("CTF{decoded_chain}" in text for text in texts), texts)

    def test_single_byte_xor_auto_decode(self) -> None:
        plain = b"CTF{xor_chain}"
        key = 0x5A
        path = self.task_dir / "input" / "encoded.bin"
        path.write_bytes(bytes(value ^ key for value in plain))
        result = auto_decode(self.tasks, self.task_id, "input/encoded.bin", max_depth=1)
        self.assertTrue(result["ok"], result)
        self.assertTrue(
            any("CTF{xor_chain}" in candidate["text_preview"] for candidate in result["data"]["candidates"]),
            result,
        )

    def test_base64_then_xor_auto_decode(self) -> None:
        plain = b"FLAG{base64_then_xor}"
        encrypted = bytes(value ^ 0x37 for value in plain)
        path = self.task_dir / "input" / "chain.txt"
        path.write_text(base64.b64encode(encrypted).decode("ascii"), encoding="ascii")
        result = auto_decode(self.tasks, self.task_id, "input/chain.txt", max_depth=2)
        self.assertTrue(result["ok"], result)
        self.assertTrue(
            any("FLAG{base64_then_xor}" in candidate["text_preview"] for candidate in result["data"]["candidates"]),
            result,
        )

    def test_zip_extraction_and_traversal_rejection(self) -> None:
        good = self.task_dir / "input" / "good.zip"
        with zipfile.ZipFile(good, "w") as archive:
            archive.writestr("nested/flag.txt", "CTF{archive_member}")
        result = archive_inspect(self.tasks, self.task_id, "input/good.zip", extract=True)
        self.assertTrue(result["ok"], result)
        extracted = self.task_dir / result["data"]["output_dir"] / "nested" / "flag.txt"
        self.assertEqual(extracted.read_text(encoding="utf-8"), "CTF{archive_member}")

        bad = self.task_dir / "input" / "bad.zip"
        with zipfile.ZipFile(bad, "w") as archive:
            archive.writestr("../../escape.txt", "not allowed")
        rejected = archive_inspect(self.tasks, self.task_id, "input/bad.zip", extract=True)
        self.assertFalse(rejected["ok"])
        self.assertIn("escapes extraction root", rejected["error"]["message"])

    def test_python_bytecode_static_disassembly(self) -> None:
        source = self.task_dir / "input" / "challenge.py"
        source.write_text(
            "def main():\n"
            "    return 'CTF{bytecode_constant}'\n",
            encoding="utf-8",
        )
        compiled = self.task_dir / "input" / "challenge.pyc"
        py_compile.compile(str(source), cfile=str(compiled), doraise=True)
        result = reverse_static(self.tasks, self.task_id, "input/challenge.pyc")
        self.assertTrue(result["ok"], result)
        constants = "\n".join(result["data"]["details"]["constants"])
        self.assertIn("CTF{bytecode_constant}", constants)


if __name__ == "__main__":
    unittest.main()
