from __future__ import annotations

import re
import base64
import json
import hashlib
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .evidence import EvidenceLedger
from .models import ToolError, envelope, utc_now
from .task import TaskManager
from .util import PolicyError, atomic_write_json, read_json, resolve_within


DEFAULT_FLAG_PATTERNS = [
    r"(?i)\b(?:flag|ctf|htb|picoctf|flagyard)\{[^}\r\n]{1,512}\}",
    r"\b[A-Fa-f0-9]{32}\b",
]


def discover_candidates(text: str, patterns: list[str] | None = None) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for pattern in patterns or DEFAULT_FLAG_PATTERNS:
        try:
            for match in re.finditer(pattern, text):
                value = match.group(0).strip()
                if value not in seen:
                    seen.add(value)
                    found.append(value)
        except re.error as exc:
            raise ValueError(f"invalid flag pattern {pattern!r}: {exc}") from exc
    return found


def add_candidate(
    task_manager: TaskManager,
    task_id: str,
    candidate: str,
    *,
    source: str,
    evidence_file: str | None = None,
) -> dict[str, Any]:
    try:
        candidate = candidate.strip()
        if not candidate or "\x00" in candidate or len(candidate) > 2048:
            raise PolicyError("candidate flag is empty or invalid")
        task_dir = task_manager.get_dir(task_id)
        ledger = EvidenceLedger(task_dir)
        state = read_json(task_dir / "state.json")
        candidates = state.setdefault("candidate_flags", [])
        if candidate not in {item.get("value") for item in candidates}:
            record = {
                "value": candidate,
                "source": source,
                "evidence_file": evidence_file,
                "created_at": utc_now(),
                "assurance": "unverified",
            }
            candidates.append(record)
            atomic_write_json(task_dir / "state.json", state)
            ledger.event("flag_candidate", **record)
        else:
            record = next(item for item in candidates if item.get("value") == candidate)
        return envelope(
            "ctf_flag_candidate",
            ok=True,
            task_id=task_id,
            data={"candidate": record, "verified": False},
            warnings=["A candidate flag is not a confirmed solve."],
        )
    except Exception as exc:
        return envelope(
            "ctf_flag_candidate",
            ok=False,
            task_id=task_id,
            exit_code=1,
            error=ToolError("FLAG_CANDIDATE_FAILED", str(exc)),
        )


def verify_flag(
    task_manager: TaskManager,
    task_id: str,
    candidate: str,
    *,
    expected_regex: str | None = None,
    evidence_file: str | None = None,
) -> dict[str, Any]:
    try:
        candidate = candidate.strip()
        task_dir = task_manager.get_dir(task_id)
        ledger = EvidenceLedger(task_dir)
        evidence_checked = False
        evidence_match = False
        if expected_regex:
            try:
                regex = re.compile(expected_regex)
            except re.error as exc:
                raise PolicyError(f"invalid expected regex: {exc}") from exc
            if not regex.fullmatch(candidate):
                return envelope(
                    "ctf_flag_verify",
                    ok=False,
                    task_id=task_id,
                    data={"candidate": candidate, "assurance": "rejected"},
                    error=ToolError("FLAG_FORMAT_REJECTED", "candidate does not match expected regex"),
                )
        if evidence_file:
            path = resolve_within(task_dir, evidence_file, must_exist=True)
            if not path.is_file():
                raise PolicyError("evidence path is not a file")
            evidence_checked = True
            raw = path.read_bytes()
            evidence_match = candidate.encode("utf-8") in raw
            if not evidence_match:
                return envelope(
                    "ctf_flag_verify",
                    ok=False,
                    task_id=task_id,
                    data={"candidate": candidate, "assurance": "rejected"},
                    error=ToolError("EVIDENCE_MISMATCH", "candidate was not found in evidence file"),
                )
        assurance = "reproducible_evidence" if evidence_checked else "format_only"
        verified = assurance == "reproducible_evidence"
        state = read_json(task_dir / "state.json")
        verification = {
            "value": candidate,
            "assurance": assurance,
            "verified": verified,
            "expected_regex": expected_regex,
            "evidence_file": evidence_file,
            "verified_at": utc_now(),
        }
        if verified:
            state.setdefault("verified_flags", []).append(verification)
            state["status"] = "VERIFIED"
        atomic_write_json(task_dir / "state.json", state)
        ledger.event("flag_verification", **verification)
        return envelope(
            "ctf_flag_verify",
            ok=verified,
            task_id=task_id,
            data=verification,
            warnings=[] if verified else ["Format-only checks do not prove the flag is accepted."],
            error=None
            if verified
            else ToolError(
                "UNVERIFIED_FLAG",
                "no external validator or matching evidence was supplied",
                retryable=False,
            ),
        )
    except Exception as exc:
        return envelope(
            "ctf_flag_verify",
            ok=False,
            task_id=task_id,
            exit_code=1,
            error=ToolError("FLAG_VERIFY_FAILED", str(exc)),
        )


def scan_flags(
    task_manager: TaskManager,
    task_id: str,
    *,
    evidence_file: str,
    patterns: list[str] | None = None,
    max_bytes: int = 8 * 1024 * 1024,
) -> dict[str, Any]:
    try:
        task_dir = task_manager.get_dir(task_id)
        path = resolve_within(task_dir, evidence_file, must_exist=True)
        if not path.is_file():
            raise PolicyError("evidence path is not a file")
        raw = path.read_bytes()[: max(1024, min(max_bytes, 64 * 1024 * 1024))]
        text = raw.decode("utf-8", errors="replace")
        candidates = discover_candidates(text, patterns)
        registered = []
        for candidate in candidates[:200]:
            result = add_candidate(
                task_manager,
                task_id,
                candidate,
                source=f"automatic scan of {path.relative_to(task_dir).as_posix()}",
                evidence_file=path.relative_to(task_dir).as_posix(),
            )
            if result.get("ok"):
                registered.append(result["data"]["candidate"])
        EvidenceLedger(task_dir).event(
            "flag_scan",
            evidence_file=path.relative_to(task_dir).as_posix(),
            candidates=[item.get("value") for item in registered],
        )
        return envelope(
            "ctf_flag_scan",
            ok=True,
            task_id=task_id,
            data={
                "evidence_file": path.relative_to(task_dir).as_posix(),
                "candidates": registered,
                "count": len(registered),
            },
            warnings=[] if registered else ["No flag-like strings were discovered."],
        )
    except Exception as exc:
        return envelope(
            "ctf_flag_scan",
            ok=False,
            task_id=task_id,
            exit_code=1,
            error=ToolError("FLAG_SCAN_FAILED", str(exc)),
        )


def submit_flag(
    task_manager: TaskManager,
    task_id: str,
    *,
    candidate: str,
    submission_url: str,
    expected_success_regex: str,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    body_template: str = '{"flag":"{{flag_json}}" }',
    timeout_seconds: float = 15.0,
) -> dict[str, Any]:
    from .http_client import perform_request

    try:
        candidate = candidate.strip()
        if not candidate or len(candidate) > 2048:
            raise PolicyError("candidate flag is empty or invalid")
        if not expected_success_regex.strip():
            raise PolicyError("expected_success_regex is required for platform verification")
        try:
            success_pattern = re.compile(expected_success_regex)
        except re.error as exc:
            raise PolicyError(f"invalid success regex: {exc}") from exc
        if "{{flag_json}}" in body_template:
            body = body_template.replace("{{flag_json}}", json.dumps(candidate)[1:-1])
        else:
            body = body_template.replace("{{flag}}", candidate)
        request_headers = dict(headers or {})
        if method.upper() in {"POST", "PUT", "PATCH"} and not any(
            key.lower() == "content-type" for key in request_headers
        ):
            request_headers["Content-Type"] = "application/json"
        response = perform_request(
            task_manager,
            task_id,
            submission_url,
            method=method,
            headers=request_headers,
            body=body,
            timeout_seconds=timeout_seconds,
            follow_redirects=False,
        )
        task_dir = task_manager.get_dir(task_id)
        ledger = EvidenceLedger(task_dir)
        status = int((response.get("data") or {}).get("status", 0))
        response_text = str((response.get("data") or {}).get("text") or "")
        accepted = bool(response.get("ok")) and 200 <= status < 300 and bool(success_pattern.search(response_text))
        artifact = task_dir / "artifacts" / "platform-submission.json"
        artifact.write_text(
            json.dumps(
                {
                    "task_id": task_id,
                    "submission_url": submission_url,
                    "method": method.upper(),
                    "status": status,
                    "candidate": candidate,
                    "accepted": accepted,
                    "expected_success_regex": expected_success_regex,
                    "response_artifact": (response.get("artifacts") or [None])[0],
                    "response_text_preview": response_text[:4000],
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        artifact_record = ledger.artifact(
            artifact,
            kind="application/json",
            source_tool="ctf_flag_submit",
        )
        if not accepted:
            ledger.event(
                "platform_submission_rejected",
                candidate=candidate,
                status=status,
                evidence_file=artifact_record["path"],
            )
            return envelope(
                "ctf_flag_submit",
                ok=False,
                task_id=task_id,
                data={"status": status, "accepted": False, "candidate": candidate},
                artifacts=[artifact_record],
                error=ToolError("PLATFORM_REJECTED", "submission response did not satisfy the success regex"),
            )

        state = read_json(task_dir / "state.json")
        state.setdefault("candidate_flags", []).append(
            {
                "value": candidate,
                "source": "platform submission",
                "evidence_file": artifact_record["path"],
                "created_at": utc_now(),
                "assurance": "platform_verified",
            }
        )
        verification = {
            "value": candidate,
            "assurance": "platform_verified",
            "verified": True,
            "validator": "platform-submit-regex",
            "evidence_file": artifact_record["path"],
            "submission_url": submission_url,
            "verified_at": utc_now(),
        }
        state.setdefault("verified_flags", []).append(verification)
        state["status"] = "VERIFIED"
        atomic_write_json(task_dir / "state.json", state)
        ledger.event("flag_verification", **verification)
        return envelope(
            "ctf_flag_submit",
            ok=True,
            task_id=task_id,
            data=verification,
            artifacts=[artifact_record],
        )
    except Exception as exc:
        return envelope(
            "ctf_flag_submit",
            ok=False,
            task_id=task_id,
            exit_code=1,
            error=ToolError("FLAG_SUBMISSION_FAILED", str(exc)),
        )


def validate_juice_shop_admin(
    task_manager: TaskManager,
    task_id: str,
    token: str,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        task_dir = task_manager.get_dir(task_id)
        scope = read_json(task_dir / "scope.json")
        parsed_target = urllib.parse.urlsplit(str(scope["target_url"]))
        if parsed_target.hostname not in {"127.0.0.1", "localhost"}:
            raise PolicyError("Juice Shop validator only accepts a loopback lab target")
        port = parsed_target.port or 80
        token = token.strip()
        if not token or len(token) > 8192:
            raise PolicyError("invalid Juice Shop token")
        base_url = f"{parsed_target.scheme}://{parsed_target.hostname}:{port}"
        whoami_url = base_url + "/rest/user/whoami"
        request = urllib.request.Request(
            whoami_url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read(1024 * 1024)
            status = response.status
        jwt_parts = token.split(".")
        if len(jwt_parts) != 3:
            raise PolicyError("Juice Shop token is not a JWT")
        payload = jwt_parts[1] + "=" * (-len(jwt_parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
        user = claims.get("data") if isinstance(claims.get("data"), dict) else {}
        email = str(user.get("email", ""))
        role = str(user.get("role", ""))
        challenge_url = (
            base_url
            + "/api/Challenges/?"
            + urllib.parse.urlencode({"name": "Login Admin"})
        )
        challenge_request = urllib.request.Request(
            challenge_url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        with urllib.request.urlopen(challenge_request, timeout=15) as response:
            challenge_raw = response.read(1024 * 1024)
            challenge_status = response.status
        challenge_data = json.loads(challenge_raw.decode("utf-8"))
        challenge_rows = challenge_data.get("data") or []
        challenge_verified = (
            challenge_status == 200
            and challenge_rows
            and any(
                row.get("name") == "Login Admin" and row.get("solved") is True
                for row in challenge_rows
            )
        )
        if status != 200 or email.lower() != "admin@juice-sh.op" or role != "admin" or not challenge_verified:
            return envelope(
                "ctf_validate_juice_shop_admin",
                ok=False,
                task_id=task_id,
                duration_ms=int((time.monotonic() - started) * 1000),
                data={
                    "status": status,
                    "challenge_status": challenge_status,
                    "email": email,
                    "role": role,
                    "challenge_verified": challenge_verified,
                },
                error=ToolError("LOCAL_VALIDATION_REJECTED", "token does not identify the Juice Shop admin"),
            )
        ledger = EvidenceLedger(task_dir)
        artifact = task_dir / "artifacts" / "juice-shop-login-admin-evidence.json"
        sanitized_claims = {
            "data": {"email": email, "role": role, "id": user.get("id")},
            "bid": claims.get("bid"),
            "iat": claims.get("iat"),
        }
        artifact.write_text(
            json.dumps(
                {
                    "whoami_status": status,
                    "whoami": json.loads(raw.decode("utf-8")),
                    "jwt_claims_sanitized": sanitized_claims,
                    "challenge_status": challenge_status,
                    "challenge": challenge_rows[0],
                    "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        artifact_record = ledger.artifact(
            artifact,
            kind="application/json",
            source_tool="ctf_validate_juice_shop_admin",
        )
        flag = "FLAG{JUICE_SHOP_LOGIN_ADMIN}"
        state = read_json(task_dir / "state.json")
        verification = {
            "value": flag,
            "assurance": "local_validator_verified",
            "verified": True,
            "validator": "juice-shop-admin-whoami",
            "evidence_file": artifact.relative_to(task_dir).as_posix(),
            "verified_at": utc_now(),
        }
        state.setdefault("verified_flags", []).append(verification)
        state["status"] = "VERIFIED"
        atomic_write_json(task_dir / "state.json", state)
        ledger.event(
            "flag_verification",
            value=flag,
            assurance="local_validator_verified",
            validator="juice-shop-admin-whoami",
            evidence_file=verification["evidence_file"],
            user_email=email,
        )
        return envelope(
            "ctf_validate_juice_shop_admin",
            ok=True,
            task_id=task_id,
            duration_ms=int((time.monotonic() - started) * 1000),
            data={
                **verification,
                "admin_email": email,
                "role": role,
                "challenge_verified": True,
                "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
            },
            artifacts=[artifact_record],
        )
    except Exception as exc:
        return envelope(
            "ctf_validate_juice_shop_admin",
            ok=False,
            task_id=task_id,
            duration_ms=int((time.monotonic() - started) * 1000),
            error=ToolError("LOCAL_VALIDATION_FAILED", str(exc)),
        )
