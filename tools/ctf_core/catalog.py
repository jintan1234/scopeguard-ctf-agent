from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .util import project_root, read_json


def catalog_path(root: Path | None = None) -> Path:
    return (root or project_root()) / "config" / "tool-catalog.json"


def load_catalog(root: Path | None = None) -> dict[str, Any]:
    return read_json(catalog_path(root))


def tool_status(root: Path | None = None) -> dict[str, Any]:
    catalog = load_catalog(root)
    tools: list[dict[str, Any]] = []
    for item in catalog.get("tools", []):
        command = item.get("command")
        found = shutil.which(command) if command else None
        if not found and item.get("fallback_path"):
            fallback = Path(item["fallback_path"])
            if fallback.is_file():
                found = str(fallback)
        tools.append({**item, "detected": bool(found), "detected_path": found})
    return {
        "catalog_version": catalog.get("version"),
        "tools": tools,
        "detected_count": sum(1 for item in tools if item["detected"]),
        "total_count": len(tools),
    }
