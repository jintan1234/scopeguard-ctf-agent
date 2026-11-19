from __future__ import annotations

import argparse
import json
from pathlib import Path

from smoke_client import McpClient


PROJECT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--depth", type=int, default=12)
    args = parser.parse_args()
    client = McpClient()
    try:
        initialized = client.send(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "ctf-page-probe", "version": "0.1.0"},
            },
        )
        client.notify("notifications/initialized")
        navigated = client.call("browser_navigate", {"url": args.url})
        snapshot = client.call("browser_snapshot", {"depth": args.depth})
        network = client.call(
            "browser_network_requests",
            {"all": True, "filter": "/rest/|/api/"},
        )
        output = {
            "ok": not navigated.get("isError") and not snapshot.get("isError"),
            "server": initialized.get("serverInfo"),
            "navigate": "".join(
                item.get("text", "")
                for item in navigated.get("content", [])
                if item.get("type") == "text"
            )[:4000],
            "snapshot": "".join(
                item.get("text", "")
                for item in snapshot.get("content", [])
                if item.get("type") == "text"
            )[:12000],
            "network": "".join(
                item.get("text", "")
                for item in network.get("content", [])
                if item.get("type") == "text"
            )[:6000],
        }
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0 if output["ok"] else 1
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
