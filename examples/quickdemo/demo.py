#!/usr/bin/env python3
"""Run an offline end-to-end task using the local synthetic Crypto fixture."""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / "tools"))

from ctf_core.crypto_ops import auto_decode
from ctf_core.flagops import add_candidate, verify_flag
from ctf_core.report import write_report
from ctf_core.task import TaskManager


def main() -> int:
    fixture = PROJECT / "tests" / "fixtures" / "generated" / "crypto-chain.txt"
    if not fixture.is_file():
        raise SystemExit(f"fixture missing: {fixture}")

    with tempfile.TemporaryDirectory(prefix="scopeguard-demo-") as raw:
        root = Path(raw)
        manager = TaskManager(root=root)
        created = manager.create(
            "http://127.0.0.1:3000/",
            "Offline synthetic Crypto demo.",
            authorized=True,
        )
        task_id = created["task"]["task_id"]
        task_dir = Path(created["path"])

        input_file = task_dir / "input" / "crypto-chain.txt"
        shutil.copy2(fixture, input_file)

        decoded = auto_decode(
            manager,
            task_id,
            input_file.relative_to(task_dir).as_posix(),
        )
        if not decoded["ok"]:
            raise SystemExit(f"auto-decode failed: {decoded}")

        candidates = decoded["data"]["candidates"]
        flags = [
            flag
            for candidate in candidates
            for flag in candidate.get("flags", [])
        ]
        if not flags:
            raise SystemExit("no Flag candidate found")

        candidate = flags[0]
        evidence_file = decoded["artifacts"][0]["path"]

        added = add_candidate(
            manager,
            task_id,
            candidate,
            source="offline auto-decode demo",
            evidence_file=evidence_file,
        )
        verified = verify_flag(
            manager,
            task_id,
            candidate,
            expected_regex=r"FLAG\{[A-Z0-9_]+\}",
            evidence_file=evidence_file,
        )
        report = write_report(
            manager,
            task_id,
            challenge_type="crypto",
            summary="Decoded a synthetic Base64 plus XOR fixture.",
        )

        print(f"task_id={task_id}")
        print(f"candidate={candidate}")
        print(f"candidate_registered={added['ok']}")
        print(f"verified={verified['ok']}")
        print(f"assurance={verified['data']['assurance']}")
        print(f"decode_artifact={evidence_file}")
        print(f"report_ok={report['ok']}")
        print(f"temporary_task={task_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
