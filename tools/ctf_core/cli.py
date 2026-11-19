from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .catalog import tool_status
from .analysis_ops import archive_inspect, reverse_static
from .crypto_ops import auto_decode
from .docker_broker import (
    build as broker_build,
    create as broker_create,
    execute as broker_execute,
    status as broker_status,
    stop as broker_stop,
)
from .evidence_ops import record_action, register_artifact
from .fileops import analyze_pcap, inspect_file, inspect_image
from .flagops import add_candidate, scan_flags, submit_flag, validate_juice_shop_admin, verify_flag
from .http_client import perform_request
from . import local_lab
from .models import ToolError, envelope, utc_now
from .remote_ops import execute_remote_http, execute_ssh
from .report import write_report
from .task import TaskManager
from .util import project_root


def _print(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def _add_task_id(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--task-id", required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ctf-agent")
    parser.add_argument("--root", default=None, help="Project root override.")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("task-create")
    create.add_argument("--target", required=True)
    create.add_argument("--instruction", required=True)
    create.add_argument("--authorized", action="store_true")
    create.add_argument("--allow-host", action="append", default=[])
    create.add_argument("--allow-port", action="append", type=int, default=[])
    create.add_argument("--allow-scheme", action="append", default=[])
    create.add_argument("--allow-redirect-host", action="append", default=[])
    create.add_argument("--attachment", action="append", default=[])

    status = sub.add_parser("task-status")
    _add_task_id(status)

    task_update = sub.add_parser("task-update")
    _add_task_id(task_update)
    task_update.add_argument(
        "--phase",
        choices=["SCOPED", "RECON", "CLASSIFIED", "EXPLOITING", "VERIFIED", "REPORTED", "BLOCKED"],
    )
    task_update.add_argument("--challenge-type")
    task_update.add_argument("--primary-hypothesis")
    task_update.add_argument("--fallback-hypothesis")
    task_update.add_argument("--next-action", action="append", default=[])
    task_update.add_argument("--unresolved", action="append", default=[])
    task_update.add_argument("--progress-note")

    file_inspect = sub.add_parser("file-inspect")
    _add_task_id(file_inspect)
    file_inspect.add_argument("--file", required=True)
    file_inspect.add_argument("--max-strings", type=int, default=80)

    image = sub.add_parser("image-inspect")
    _add_task_id(image)
    image.add_argument("--file", required=True)

    http = sub.add_parser("http-request")
    _add_task_id(http)
    http.add_argument("--url", required=True)
    http.add_argument("--method", default="GET")
    http.add_argument("--header", action="append", default=[])
    http_body = http.add_mutually_exclusive_group()
    http_body.add_argument("--body")
    http_body.add_argument("--body-file")
    http.add_argument("--timeout", type=float, default=15.0)
    http.add_argument("--max-bytes", type=int, default=2 * 1024 * 1024)
    http.add_argument("--follow-redirects", action="store_true")
    http.add_argument("--insecure-tls", action="store_true")

    pcap = sub.add_parser("pcap-analyze")
    _add_task_id(pcap)
    pcap.add_argument("--file", required=True)
    pcap.add_argument("--display-filter")
    pcap.add_argument("--timeout", type=int, default=60)

    decode = sub.add_parser("auto-decode")
    _add_task_id(decode)
    decode.add_argument("--file", required=True)
    decode.add_argument("--operations", action="append", default=[])
    decode.add_argument("--xor-key", type=int)
    decode.add_argument("--max-depth", type=int, default=4)

    archive = sub.add_parser("archive-inspect")
    _add_task_id(archive)
    archive.add_argument("--file", required=True)
    archive.add_argument("--extract", action="store_true")

    reverse = sub.add_parser("reverse-static")
    _add_task_id(reverse)
    reverse.add_argument("--file", required=True)

    sandbox_status = sub.add_parser("sandbox-status")
    sandbox_build = sub.add_parser("sandbox-build")
    sandbox_build.add_argument(
        "--profile",
        required=True,
        choices=["analysis", "reverse", "pwn", "web", "crypto", "remote"],
    )
    sandbox_build.add_argument("--timeout", type=int, default=1800)

    sandbox_create = sub.add_parser("sandbox-create")
    _add_task_id(sandbox_create)
    sandbox_create.add_argument(
        "--profile",
        required=True,
        choices=["analysis", "reverse", "pwn", "web", "crypto", "remote"],
    )

    sandbox_exec = sub.add_parser("sandbox-exec")
    _add_task_id(sandbox_exec)
    sandbox_exec.add_argument("--container-id", required=True)
    command_group = sandbox_exec.add_mutually_exclusive_group(required=True)
    command_group.add_argument("--command", dest="sandbox_command")
    command_group.add_argument("--command-file")
    sandbox_exec.add_argument("--timeout", type=int, default=60)

    sandbox_stop = sub.add_parser("sandbox-stop")
    _add_task_id(sandbox_stop)
    sandbox_stop.add_argument("--container-id", required=True)

    lab_build = sub.add_parser("lab-build")
    lab_build.add_argument("--lab", required=True, choices=["juice-shop"])
    lab_build.add_argument("--timeout", type=int, default=1800)

    lab_start = sub.add_parser("lab-start")
    lab_start.add_argument("--lab", required=True, choices=["juice-shop"])
    lab_start.add_argument("--port", type=int, default=3000)

    lab_stop = sub.add_parser("lab-stop")
    lab_stop.add_argument("--lab", required=True, choices=["juice-shop"])

    lab_status = sub.add_parser("lab-status")
    lab_status.add_argument("--lab", required=True, choices=["juice-shop"])

    flag = sub.add_parser("flag-candidate")
    _add_task_id(flag)
    flag.add_argument("--candidate", required=True)
    flag.add_argument("--source", required=True)
    flag.add_argument("--evidence-file")

    verify = sub.add_parser("flag-verify")
    _add_task_id(verify)
    verify.add_argument("--candidate", required=True)
    verify.add_argument("--expected-regex")
    verify.add_argument("--evidence-file")

    scan = sub.add_parser("flag-scan")
    _add_task_id(scan)
    scan.add_argument("--evidence-file", required=True)
    scan.add_argument("--pattern", action="append", default=[])
    scan.add_argument("--max-bytes", type=int, default=8 * 1024 * 1024)

    submit = sub.add_parser("flag-submit")
    _add_task_id(submit)
    submit.add_argument("--candidate", required=True)
    submit.add_argument("--submission-url", required=True)
    submit.add_argument("--expected-success-regex", required=True)
    submit.add_argument("--method", default="POST")
    submit.add_argument("--header", action="append", default=[])
    submit.add_argument("--body-template", default='{"flag":"{{flag_json}}" }')
    submit.add_argument("--timeout", type=float, default=15.0)

    evidence = sub.add_parser("evidence-record")
    _add_task_id(evidence)
    evidence.add_argument("--description", required=True)
    evidence.add_argument("--command", required=True)
    evidence.add_argument("--cwd", default="")
    evidence.add_argument("--exit-code", type=int)
    evidence.add_argument("--duration-ms", type=int, default=0)
    evidence.add_argument("--stdout", default="")
    evidence.add_argument("--stderr", default="")
    evidence.add_argument("--truncated", action="store_true")
    evidence.add_argument("--artifact-file", action="append", default=[])

    artifact = sub.add_parser("register-artifact")
    _add_task_id(artifact)
    artifact.add_argument("--artifact-file", required=True)
    artifact.add_argument("--kind", default="file")

    remote = sub.add_parser("remote-exec")
    _add_task_id(remote)
    remote.add_argument("--host", required=True)
    remote.add_argument("--username", required=True)
    remote.add_argument("--command", required=True)
    remote.add_argument("--port", type=int, default=22)
    remote.add_argument("--identity-file")
    remote.add_argument("--known-hosts-file")
    remote.add_argument("--timeout", type=int, default=60)
    remote.add_argument("--destructive-confirmed", action="store_true")

    remote_http = sub.add_parser("remote-http")
    _add_task_id(remote_http)
    remote_http.add_argument("--ssh-host", required=True)
    remote_http.add_argument("--ssh-username", required=True)
    remote_http.add_argument("--ssh-port", type=int, required=True)
    remote_http.add_argument("--target-url", required=True)
    remote_http.add_argument("--method", default="GET")
    remote_http.add_argument("--header", action="append", default=[])
    remote_http.add_argument("--body")
    remote_http.add_argument("--identity-file")
    remote_http.add_argument("--known-hosts-file")
    remote_http.add_argument("--timeout", type=int, default=60)

    juice_verify = sub.add_parser("validate-juice-admin")
    _add_task_id(juice_verify)
    token_group = juice_verify.add_mutually_exclusive_group(required=True)
    token_group.add_argument("--token")
    token_group.add_argument("--token-file")

    report = sub.add_parser("report")
    _add_task_id(report)
    report.add_argument("--challenge-type", default="unknown")
    report.add_argument("--summary", default="")
    report.add_argument("--unresolved", action="append", default=[])

    sub.add_parser("tool-catalog")
    return parser


def _headers(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        key, separator, content = value.partition(":")
        if not separator:
            raise ValueError(f"invalid header, expected Name:Value: {value}")
        result[key.strip()] = content.strip()
    return result


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    root = Path(args.root).resolve() if args.root else project_root()
    tasks = TaskManager(root)
    started_at = utc_now()
    command_tools = {
        "file-inspect": "ctf_file_inspect",
        "image-inspect": "ctf_inspect_image",
        "http-request": "ctf_http_request",
        "pcap-analyze": "ctf_analyze_pcap",
        "auto-decode": "ctf_auto_decode",
        "archive-inspect": "ctf_archive_inspect",
        "reverse-static": "ctf_reverse_static",
        "sandbox-create": "ctf_sandbox_create",
        "sandbox-exec": "ctf_sandbox_exec",
        "sandbox-stop": "ctf_sandbox_stop",
        "flag-candidate": "ctf_flag_candidate",
        "flag-verify": "ctf_flag_verify",
        "flag-scan": "ctf_flag_scan",
        "flag-submit": "ctf_flag_submit",
        "task-update": "ctf_task_update",
        "evidence-record": "ctf_evidence_record",
        "register-artifact": "ctf_register_artifact",
        "remote-exec": "ctf_remote_exec",
        "remote-http": "ctf_remote_http",
        "validate-juice-admin": "ctf_validate_juice_shop_admin",
    }
    budget_decision = None
    tool_name = command_tools.get(args.command)
    if tool_name and getattr(args, "task_id", None):
        budget_decision = tasks.begin_tool_call(
            args.task_id,
            tool_name,
            vars(args),
            exempt=False,
        )
        if not budget_decision.get("allowed"):
            result = envelope(
                tool_name,
                ok=False,
                task_id=args.task_id,
                started_at=started_at,
                exit_code=1,
                data={"budget": budget_decision.get("budget")},
                error=ToolError(
                    str(budget_decision.get("code", "TOOL_BLOCKED")),
                    str(budget_decision.get("message", "tool call blocked")),
                ),
            )
            _print(result)
            return 1
    try:
        if args.command == "task-create":
            result = tasks.create(
                args.target,
                args.instruction,
                authorized=args.authorized,
                allowed_hosts=args.allow_host,
                allowed_ports=args.allow_port,
                allowed_schemes=args.allow_scheme,
                allowed_redirect_hosts=args.allow_redirect_host,
                attachments=args.attachment,
            )
            result = envelope(
                "ctf_task_create",
                ok=True,
                task_id=result["task"]["task_id"],
                started_at=started_at,
                data=result,
            )
        elif args.command == "task-status":
            result = envelope(
                "ctf_task_status",
                ok=True,
                task_id=args.task_id,
                started_at=started_at,
                data=tasks.get(args.task_id),
            )
        elif args.command == "task-update":
            result = envelope(
                "ctf_task_update",
                ok=True,
                task_id=args.task_id,
                started_at=started_at,
                data=tasks.update_workflow(
                    args.task_id,
                    phase=args.phase,
                    challenge_type=args.challenge_type,
                    primary_hypothesis=args.primary_hypothesis,
                    fallback_hypothesis=args.fallback_hypothesis,
                    next_actions=args.next_action or None,
                    unresolved=args.unresolved or None,
                    progress_note=args.progress_note,
                ),
            )
        elif args.command == "file-inspect":
            result = inspect_file(tasks, args.task_id, args.file, max_strings=args.max_strings)
        elif args.command == "image-inspect":
            result = inspect_image(tasks, args.task_id, args.file)
        elif args.command == "http-request":
            body = args.body
            if args.body_file:
                body = Path(args.body_file).read_text(encoding="utf-8")
            result = perform_request(
                tasks,
                args.task_id,
                args.url,
                method=args.method,
                headers=_headers(args.header),
                body=body,
                timeout_seconds=args.timeout,
                max_response_bytes=args.max_bytes,
                follow_redirects=args.follow_redirects,
                insecure_tls=args.insecure_tls,
            )
        elif args.command == "pcap-analyze":
            result = analyze_pcap(
                tasks,
                args.task_id,
                args.file,
                display_filter=args.display_filter,
                timeout_seconds=args.timeout,
            )
        elif args.command == "auto-decode":
            result = auto_decode(
                tasks,
                args.task_id,
                args.file,
                operations=args.operations or None,
                xor_key=args.xor_key,
                max_depth=args.max_depth,
            )
        elif args.command == "archive-inspect":
            result = archive_inspect(
                tasks,
                args.task_id,
                args.file,
                extract=args.extract,
            )
        elif args.command == "reverse-static":
            result = reverse_static(tasks, args.task_id, args.file)
        elif args.command == "sandbox-status":
            result = broker_status(tasks)
        elif args.command == "sandbox-build":
            result = broker_build(tasks, args.profile, args.timeout)
        elif args.command == "sandbox-create":
            result = broker_create(tasks, args.task_id, args.profile)
        elif args.command == "sandbox-exec":
            command = args.sandbox_command
            if args.command_file:
                command_path = Path(args.command_file).resolve()
                command = command_path.read_text(encoding="utf-8")
            result = broker_execute(
                tasks,
                args.task_id,
                args.container_id,
                command,
                timeout_seconds=args.timeout,
            )
        elif args.command == "sandbox-stop":
            result = broker_stop(tasks, args.task_id, args.container_id)
        elif args.command == "lab-build":
            result = local_lab.build(tasks, args.lab, args.timeout)
        elif args.command == "lab-start":
            result = local_lab.start(tasks, args.lab, args.port)
        elif args.command == "lab-stop":
            result = local_lab.stop(tasks, args.lab)
        elif args.command == "lab-status":
            result = local_lab.status(tasks, args.lab)
        elif args.command == "flag-candidate":
            result = add_candidate(
                tasks,
                args.task_id,
                args.candidate,
                source=args.source,
                evidence_file=args.evidence_file,
            )
        elif args.command == "flag-verify":
            result = verify_flag(
                tasks,
                args.task_id,
                args.candidate,
                expected_regex=args.expected_regex,
                evidence_file=args.evidence_file,
            )
        elif args.command == "flag-scan":
            result = scan_flags(
                tasks,
                args.task_id,
                evidence_file=args.evidence_file,
                patterns=args.pattern or None,
                max_bytes=args.max_bytes,
            )
        elif args.command == "flag-submit":
            result = submit_flag(
                tasks,
                args.task_id,
                candidate=args.candidate,
                submission_url=args.submission_url,
                expected_success_regex=args.expected_success_regex,
                method=args.method,
                headers=_headers(args.header),
                body_template=args.body_template,
                timeout_seconds=args.timeout,
            )
        elif args.command == "evidence-record":
            result = record_action(
                tasks,
                args.task_id,
                description=args.description,
                command=args.command,
                cwd=args.cwd,
                exit_code=args.exit_code,
                duration_ms=args.duration_ms,
                stdout=args.stdout,
                stderr=args.stderr,
                truncated=args.truncated,
                artifact_files=args.artifact_file,
            )
        elif args.command == "register-artifact":
            result = register_artifact(
                tasks,
                args.task_id,
                artifact_file=args.artifact_file,
                kind=args.kind,
            )
        elif args.command == "remote-exec":
            result = execute_ssh(
                tasks,
                args.task_id,
                host=args.host,
                username=args.username,
                command=args.command,
                port=args.port,
                identity_file=args.identity_file,
                known_hosts_file=args.known_hosts_file,
                timeout_seconds=args.timeout,
                destructive_confirmed=args.destructive_confirmed,
            )
        elif args.command == "remote-http":
            result = execute_remote_http(
                tasks,
                args.task_id,
                ssh_host=args.ssh_host,
                ssh_username=args.ssh_username,
                ssh_port=args.ssh_port,
                target_url=args.target_url,
                method=args.method,
                headers=_headers(args.header),
                body=args.body,
                identity_file=args.identity_file,
                known_hosts_file=args.known_hosts_file,
                timeout_seconds=args.timeout,
            )
        elif args.command == "validate-juice-admin":
            token = args.token
            if args.token_file:
                token = Path(args.token_file).read_text(encoding="utf-8").strip()
            result = validate_juice_shop_admin(tasks, args.task_id, token)
        elif args.command == "report":
            result = write_report(
                tasks,
                args.task_id,
                challenge_type=args.challenge_type,
                summary=args.summary,
                unresolved=args.unresolved,
            )
        elif args.command == "tool-catalog":
            result = envelope(
                "ctf_tool_catalog",
                ok=True,
                started_at=started_at,
                data=tool_status(root),
            )
        else:
            raise AssertionError(args.command)
    except Exception as exc:
        result = envelope(
            args.command,
            ok=False,
            task_id=getattr(args, "task_id", None),
            started_at=started_at,
            exit_code=1,
            error=ToolError("CLI_FAILED", str(exc)),
        )
    if budget_decision and budget_decision.get("allowed") and getattr(args, "task_id", None):
        try:
            tasks.finish_tool_call(args.task_id, tool_name or args.command, ok=bool(result.get("ok")))
        except Exception:
            pass
    _print(result)
    if isinstance(result, dict) and result.get("ok") is False:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
