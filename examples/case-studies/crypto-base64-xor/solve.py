#!/usr/bin/env python3
"""Run the local Base64 plus XOR challenge through ctf-control APIs."""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT / "tools"))

from ctf_core.crypto_ops import auto_decode
from ctf_core.flagops import add_candidate, verify_flag
from ctf_core.task import TaskManager


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: solve.py path/to/crypto-chain.txt")
        return 2

    source = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="crypto-case-") as raw:
        manager = TaskManager(root=Path(raw))
        created = manager.create(
            "http://127.0.0.1:3000/",
            "Historical local Base64 plus XOR challenge.",
            authorized=True,
        )
        task_id = created["task"]["task_id"]
        task_dir = Path(created["path"])
        local = task_dir / "input" / source.name
        shutil.copy2(source, local)

        result = auto_decode(
            manager,
            task_id,
            local.relative_to(task_dir).as_posix(),
        )
        if not result["ok"]:
            raise SystemExit(result)

        flags = [
            flag
            for candidate in result["data"]["candidates"]
            for flag in candidate.get("flags", [])
        ]
        if not flags:
            raise SystemExit("no Flag candidate")

        candidate = flags[0]
        evidence = result["artifacts"][0]["path"]
        add_candidate(
            manager,
            task_id,
            candidate,
            source="Base64 plus XOR auto-decode",
            evidence_file=evidence,
        )
        verified = verify_flag(
            manager,
            task_id,
            candidate,
            evidence_file=evidence,
        )
        print(f"flag={candidate}")
        print(f"assurance={verified['data']['assurance']}")
        print(f"evidence={evidence}")
        return 0 if verified["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
