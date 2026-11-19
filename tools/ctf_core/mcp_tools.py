from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Callable

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
from .fileops import analyze_pcap, find_tshark, inspect_file, inspect_image
from .flagops import add_candidate, scan_flags, submit_flag, validate_juice_shop_admin, verify_flag
from .evidence_ops import record_action, register_artifact as register_evidence_artifact
from .http_client import perform_request
from . import local_lab
from .models import ToolError, envelope
from .remote_ops import execute_remote_http, execute_ssh
from .report import write_report
from .task import TaskManager
from .util import project_root


ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


def _object_schema(
    properties: dict[str, Any], required: list[str] | None = None
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": False,
    }


def _string(description: str) -> dict[str, Any]:
    return {"type": "string", "description": description}


def _integer(description: str, *, minimum: int | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {"type": "integer", "description": description}
    if minimum is not None:
        value["minimum"] = minimum
    return value


def _boolean(description: str) -> dict[str, Any]:
    return {"type": "boolean", "description": description}


class ToolRegistry:
    def __init__(self, root: Path | None = None):
        self.root = (root or project_root()).resolve()
        self.tasks = TaskManager(self.root)
        self.handlers: dict[str, ToolHandler] = {
            "ctf_task_create": self.task_create,
            "ctf_task_status": self.task_status,
            "ctf_task_update": self.task_update,
            "ctf_tool_catalog": self.catalog,
            "ctf_file_inspect": self.file_inspect,
            "ctf_inspect_image": self.image_inspect,
            "ctf_http_request": self.http_request,
            "ctf_analyze_pcap": self.pcap_analyze,
            "ctf_auto_decode": self.auto_decode,
            "ctf_archive_inspect": self.archive_inspect,
            "ctf_reverse_static": self.reverse_static,
            "ctf_flag_candidate": self.flag_candidate,
            "ctf_flag_verify": self.flag_verify,
            "ctf_flag_scan": self.flag_scan,
            "ctf_flag_submit": self.flag_submit,
            "ctf_evidence_record": self.evidence_record,
            "ctf_register_artifact": self.register_artifact,
            "ctf_remote_exec": self.remote_exec,
            "ctf_remote_http": self.remote_http,
            "ctf_validate_juice_shop_admin": self.validate_juice_admin,
            "ctf_report_write": self.report_write,
            "ctf_sandbox_status": self.sandbox_status,
            "ctf_sandbox_build": self.sandbox_build,
            "ctf_sandbox_create": self.sandbox_create,
            "ctf_sandbox_exec": self.sandbox_exec,
            "ctf_sandbox_stop": self.sandbox_stop,
            "ctf_lab_build": self.lab_build,
            "ctf_lab_start": self.lab_start,
            "ctf_lab_stop": self.lab_stop,
            "ctf_lab_status": self.lab_status,
            "ctf_doctor": self.doctor,
        }

    def definitions(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "ctf_task_create",
                "description": "Create an authorized CTF task workspace and scope manifest.",
                "inputSchema": _object_schema(
                    {
                        "target_url": _string("Authorized CTF target URL."),
                        "instruction": _string("User solving instruction and explicit constraints."),
                        "authorized": _boolean("Must be true only when the user explicitly authorized the target."),
                        "allowed_hosts": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Exact additional hostnames explicitly in scope.",
                        },
                        "allowed_ports": {
                            "type": "array",
                            "items": {"type": "integer", "minimum": 1},
                            "description": "Ports explicitly in scope. Defaults to the target port.",
                        },
                        "allowed_schemes": {
                            "type": "array",
                            "items": {"type": "string", "enum": ["http", "https"]},
                        },
                        "allowed_redirect_hosts": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "attachments": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Host file paths to copy into the task input directory.",
                        },
                    },
                    ["target_url", "instruction", "authorized"],
                ),
            },
            {
                "name": "ctf_task_status",
                "description": "Read task state, scope, budgets and workspace path.",
                "inputSchema": _object_schema({"task_id": _string("Task identifier.")}, ["task_id"]),
            },
            {
                "name": "ctf_task_update",
                "description": "Record the current solving phase, hypotheses, next actions and progress.",
                "inputSchema": _object_schema(
                    {
                        "task_id": _string("Task identifier."),
                        "phase": {
                            "type": "string",
                            "enum": [
                                "SCOPED",
                                "RECON",
                                "CLASSIFIED",
                                "EXPLOITING",
                                "VERIFIED",
                                "REPORTED",
                                "BLOCKED",
                            ],
                        },
                        "challenge_type": _string("Current challenge classification."),
                        "primary_hypothesis": _string("Current primary hypothesis."),
                        "fallback_hypothesis": _string("Fallback hypothesis."),
                        "next_actions": {"type": "array", "items": {"type": "string"}},
                        "unresolved": {"type": "array", "items": {"type": "string"}},
                        "progress_note": _string("New evidence or progress since the previous step."),
                    },
                    ["task_id"],
                ),
            },
            {
                "name": "ctf_tool_catalog",
                "description": "Inspect the tool capabilities catalog and detect host commands.",
                "inputSchema": _object_schema({}),
            },
            {
                "name": "ctf_file_inspect",
                "description": "Hash and inspect a task-local file, including magic, entropy, strings and ZIP members.",
                "inputSchema": _object_schema(
                    {
                        "task_id": _string("Task identifier."),
                        "file": _string("Task-relative file path."),
                        "max_strings": _integer("Maximum printable strings to return.", minimum=0),
                    },
                    ["task_id", "file"],
                ),
            },
            {
                "name": "ctf_inspect_image",
                "description": "Inspect an image header, hashes and metadata. Pillow is optional.",
                "inputSchema": _object_schema(
                    {"task_id": _string("Task identifier."), "file": _string("Task-relative image path.")},
                    ["task_id", "file"],
                ),
            },
            {
                "name": "ctf_http_request",
                "description": "Perform a scope-enforced HTTP request and record request/response evidence.",
                "inputSchema": _object_schema(
                    {
                        "task_id": _string("Task identifier."),
                        "url": _string("URL within the task scope."),
                        "method": {"type": "string", "default": "GET"},
                        "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                        "body": _string("Optional UTF-8 request body."),
                        "timeout_seconds": {"type": "number", "default": 15, "minimum": 0.5},
                        "max_response_bytes": _integer("Response body cap.", minimum=1024),
                        "follow_redirects": _boolean("Follow each redirect only after scope validation."),
                        "insecure_tls": _boolean("Disable TLS verification for an authorized lab."),
                    },
                    ["task_id", "url"],
                ),
            },
            {
                "name": "ctf_analyze_pcap",
                "description": "Run fixed tshark protocol hierarchy analysis on a task-local PCAP.",
                "inputSchema": _object_schema(
                    {
                        "task_id": _string("Task identifier."),
                        "file": _string("Task-relative PCAP path."),
                        "display_filter": _string("Optional tshark display filter."),
                        "timeout_seconds": _integer("Execution timeout.", minimum=1),
                    },
                    ["task_id", "file"],
                ),
            },
            {
                "name": "ctf_auto_decode",
                "description": "Try bounded encoding/cipher chains and rank plausible plaintext or flag candidates.",
                "inputSchema": _object_schema(
                    {
                        "task_id": _string("Task identifier."),
                        "file": _string("Task-relative text or binary input."),
                        "operations": {
                            "type": "array",
                            "items": {
                                "enum": [
                                    "base64",
                                    "base32",
                                    "base85",
                                    "hex",
                                    "url",
                                    "rot13",
                                    "reverse",
                                    "atbash",
                                    "xor",
                                    "utf16le",
                                ]
                            },
                            "description": "Optional explicit transform chain. Omit for bounded auto search.",
                        },
                        "xor_key": _integer("XOR key when operations contains xor.", minimum=1),
                        "max_depth": _integer("Maximum automatic transform depth.", minimum=1),
                    },
                    ["task_id", "file"],
                ),
            },
            {
                "name": "ctf_archive_inspect",
                "description": "Inspect ZIP members and safely extract them inside the task artifacts directory.",
                "inputSchema": _object_schema(
                    {
                        "task_id": _string("Task identifier."),
                        "file": _string("Task-relative archive path."),
                        "extract": _boolean("Extract safe ZIP members after path and size validation."),
                    },
                    ["task_id", "file"],
                ),
            },
            {
                "name": "ctf_reverse_static",
                "description": "Parse PE/ELF metadata or disassemble matching Python bytecode without execution.",
                "inputSchema": _object_schema(
                    {"task_id": _string("Task identifier."), "file": _string("Task-relative binary or pyc.")},
                    ["task_id", "file"],
                ),
            },
            {
                "name": "ctf_flag_candidate",
                "description": "Record a candidate flag with source information. This does not verify it.",
                "inputSchema": _object_schema(
                    {
                        "task_id": _string("Task identifier."),
                        "candidate": _string("Candidate flag."),
                        "source": _string("Where the candidate came from."),
                        "evidence_file": _string("Optional task-relative evidence file."),
                    },
                    ["task_id", "candidate", "source"],
                ),
            },
            {
                "name": "ctf_flag_verify",
                "description": "Verify a flag by format and exact appearance in a task-local evidence artifact.",
                "inputSchema": _object_schema(
                    {
                        "task_id": _string("Task identifier."),
                        "candidate": _string("Candidate flag."),
                        "expected_regex": _string("Optional full-match flag regex."),
                        "evidence_file": _string("Task-relative proof artifact containing the flag."),
                    },
                    ["task_id", "candidate"],
                ),
            },
            {
                "name": "ctf_flag_scan",
                "description": "Scan a task-local evidence artifact and automatically register flag-like candidates.",
                "inputSchema": _object_schema(
                    {
                        "task_id": _string("Task identifier."),
                        "evidence_file": _string("Task-relative evidence file."),
                        "patterns": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional regular-expression patterns.",
                        },
                        "max_bytes": _integer("Maximum bytes scanned.", minimum=1024),
                    },
                    ["task_id", "evidence_file"],
                ),
            },
            {
                "name": "ctf_flag_submit",
                "description": "Submit a candidate to an authorized platform endpoint and verify acceptance by response regex.",
                "inputSchema": _object_schema(
                    {
                        "task_id": _string("Task identifier."),
                        "candidate": _string("Candidate flag."),
                        "submission_url": _string("In-scope platform submission URL."),
                        "expected_success_regex": _string("Required response-success regex."),
                        "method": {"type": "string", "default": "POST"},
                        "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                        "body_template": _string(
                            "Request body template using {{flag}} or JSON-escaped {{flag_json}}."
                        ),
                        "timeout_seconds": {"type": "number", "default": 15, "minimum": 0.5},
                    },
                    ["task_id", "candidate", "submission_url", "expected_success_regex"],
                ),
            },
            {
                "name": "ctf_evidence_record",
                "description": "Record an agent/remote/browser action and its hashed output artifacts in the evidence ledger.",
                "inputSchema": _object_schema(
                    {
                        "task_id": _string("Task identifier."),
                        "description": _string("What the action attempted."),
                        "command": {
                            "oneOf": [
                                {"type": "string"},
                                {"type": "array", "items": {"type": "string"}},
                            ]
                        },
                        "cwd": _string("Original working directory."),
                        "exit_code": _integer("Command exit code."),
                        "duration_ms": _integer("Duration in milliseconds.", minimum=0),
                        "stdout": _string("Bounded stdout or result text."),
                        "stderr": _string("Bounded stderr or error text."),
                        "truncated": _boolean("Whether the source output was truncated."),
                        "artifact_files": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Task-relative files produced by the action.",
                        },
                    },
                    ["task_id", "description", "command"],
                ),
            },
            {
                "name": "ctf_register_artifact",
                "description": "Hash and register an existing task-local artifact in the evidence ledger.",
                "inputSchema": _object_schema(
                    {
                        "task_id": _string("Task identifier."),
                        "artifact_file": _string("Task-relative artifact path."),
                        "kind": _string("Artifact MIME type or category."),
                    },
                    ["task_id", "artifact_file"],
                ),
            },
            {
                "name": "ctf_remote_exec",
                "description": "Execute a bounded command over OpenSSH against an exact in-scope host and port.",
                "inputSchema": _object_schema(
                    {
                        "task_id": _string("Task identifier."),
                        "host": _string("Authorized SSH host."),
                        "username": _string("SSH username."),
                        "command": _string("Remote command."),
                        "port": _integer("SSH port.", minimum=1),
                        "identity_file": _string("Optional SSH private key path."),
                        "known_hosts_file": _string("Optional known_hosts path."),
                        "timeout_seconds": _integer("Remote command timeout.", minimum=1),
                        "destructive_confirmed": _boolean(
                            "Must be true only when the user explicitly confirmed a destructive command."
                        ),
                    },
                    ["task_id", "host", "username", "command"],
                ),
            },
            {
                "name": "ctf_remote_http",
                "description": "Issue an in-scope HTTP request from an authorized SSH host using a fixed curl command.",
                "inputSchema": _object_schema(
                    {
                        "task_id": _string("Task identifier."),
                        "ssh_host": _string("Authorized SSH gateway host."),
                        "ssh_username": _string("SSH gateway username."),
                        "ssh_port": _integer("SSH gateway port.", minimum=1),
                        "target_url": _string("In-scope HTTP target reachable from the gateway."),
                        "method": {"type": "string", "default": "GET"},
                        "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                        "body": _string("Optional UTF-8 request body."),
                        "identity_file": _string("Optional SSH private key path."),
                        "known_hosts_file": _string("Optional known_hosts path."),
                        "timeout_seconds": _integer("Remote request timeout.", minimum=1),
                    },
                    [
                        "task_id",
                        "ssh_host",
                        "ssh_username",
                        "ssh_port",
                        "target_url",
                    ],
                ),
            },
            {
                "name": "ctf_validate_juice_shop_admin",
                "description": "Validate the local Juice Shop Login Admin exercise and issue a local test flag.",
                "inputSchema": _object_schema(
                    {
                        "task_id": _string("Task identifier."),
                        "token": _string("JWT returned by the authorized Juice Shop login."),
                    },
                    ["task_id", "token"],
                ),
            },
            {
                "name": "ctf_report_write",
                "description": "Generate report.md and result.json from task state and the evidence ledger.",
                "inputSchema": _object_schema(
                    {
                        "task_id": _string("Task identifier."),
                        "challenge_type": _string("web, misc, reverse, pwn, crypto, forensics, osint or unknown."),
                        "summary": _string("Concise technical summary."),
                        "unresolved": {"type": "array", "items": {"type": "string"}},
                    },
                    ["task_id"],
                ),
            },
            {
                "name": "ctf_sandbox_status",
                "description": "Query the restricted Docker broker and Linux Engine health.",
                "inputSchema": _object_schema({}),
            },
            {
                "name": "ctf_sandbox_build",
                "description": "Ask the broker to build a fixed allowlisted sandbox image.",
                "inputSchema": _object_schema(
                    {
                        "profile": {
                            "type": "string",
                            "enum": ["analysis", "reverse", "pwn", "web", "crypto", "remote"],
                        },
                        "timeout_seconds": _integer("Build timeout.", minimum=60),
                    },
                    ["profile"],
                ),
            },
            {
                "name": "ctf_sandbox_create",
                "description": "Create a resource-limited container bound to one task workspace.",
                "inputSchema": _object_schema(
                    {
                        "task_id": _string("Task identifier."),
                        "profile": {
                            "type": "string",
                            "enum": ["analysis", "reverse", "pwn", "web", "crypto", "remote"],
                        },
                    },
                    ["task_id", "profile"],
                ),
            },
            {
                "name": "ctf_sandbox_exec",
                "description": "Execute a bounded command inside a broker-created task container.",
                "inputSchema": _object_schema(
                    {
                        "task_id": _string("Task identifier."),
                        "container_id": _string("Container id or broker container name."),
                        "command": _string("Shell command executed inside /challenge/work."),
                        "timeout_seconds": _integer("Command timeout, 1-300 seconds.", minimum=1),
                    },
                    ["task_id", "container_id", "command"],
                ),
            },
            {
                "name": "ctf_sandbox_stop",
                "description": "Stop and remove a broker-created task container.",
                "inputSchema": _object_schema(
                    {
                        "task_id": _string("Task identifier."),
                        "container_id": _string("Container id or broker container name."),
                    },
                    ["task_id", "container_id"],
                ),
            },
            {
                "name": "ctf_lab_build",
                "description": "Build a fixed allowlisted local training lab image.",
                "inputSchema": _object_schema(
                    {
                        "lab": {"type": "string", "enum": ["juice-shop"]},
                        "timeout_seconds": _integer("Build timeout.", minimum=60),
                    },
                    ["lab"],
                ),
            },
            {
                "name": "ctf_lab_start",
                "description": "Start a fixed local lab bound only to 127.0.0.1.",
                "inputSchema": _object_schema(
                    {
                        "lab": {"type": "string", "enum": ["juice-shop"]},
                        "host_port": _integer("Loopback host port.", minimum=1024),
                    },
                    ["lab"],
                ),
            },
            {
                "name": "ctf_lab_stop",
                "description": "Stop the fixed local training lab container.",
                "inputSchema": _object_schema(
                    {"lab": {"type": "string", "enum": ["juice-shop"]}},
                    ["lab"],
                ),
            },
            {
                "name": "ctf_lab_status",
                "description": "Inspect the fixed local training lab state.",
                "inputSchema": _object_schema(
                    {"lab": {"type": "string", "enum": ["juice-shop"]}},
                    ["lab"],
                ),
            },
            {
                "name": "ctf_doctor",
                "description": "Report host runtime and core tool availability without installing anything.",
                "inputSchema": _object_schema({}),
            },
        ]

    def call(self, name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
        handler = self.handlers.get(name)
        if not handler:
            return envelope(
                name,
                ok=False,
                exit_code=1,
                error=ToolError("UNKNOWN_TOOL", f"unknown tool: {name}"),
            )
        values = arguments or {}
        task_id = values.get("task_id")
        decision: dict[str, Any] | None = None
        if task_id:
            try:
                decision = self.tasks.begin_tool_call(
                    str(task_id),
                    name,
                    values,
                    exempt=name in {"ctf_task_status", "ctf_report_write"},
                )
            except Exception as exc:
                return envelope(
                    name,
                    ok=False,
                    task_id=str(task_id),
                    exit_code=1,
                    error=ToolError("TASK_BUDGET_CHECK_FAILED", str(exc)),
                )
            if not decision.get("allowed"):
                return envelope(
                    name,
                    ok=False,
                    task_id=str(task_id),
                    exit_code=1,
                    data={"budget": decision.get("budget")},
                    error=ToolError(
                        str(decision.get("code", "TOOL_BLOCKED")),
                        str(decision.get("message", "tool call blocked")),
                        retryable=False,
                    ),
                )
        try:
            result = handler(values)
        except Exception as exc:
            result = envelope(
                name,
                ok=False,
                task_id=str(task_id) if task_id else None,
                exit_code=1,
                error=ToolError("TOOL_EXCEPTION", str(exc)),
            )
        if task_id and decision and not decision.get("exempt"):
            try:
                self.tasks.finish_tool_call(str(task_id), name, ok=bool(result.get("ok")))
            except Exception:
                pass
        return result

    def task_create(self, args: dict[str, Any]) -> dict[str, Any]:
        result = self.tasks.create(
            str(args["target_url"]),
            str(args["instruction"]),
            authorized=bool(args["authorized"]),
            allowed_hosts=args.get("allowed_hosts"),
            allowed_ports=args.get("allowed_ports"),
            allowed_schemes=args.get("allowed_schemes"),
            allowed_redirect_hosts=args.get("allowed_redirect_hosts"),
            attachments=args.get("attachments"),
        )
        return envelope("ctf_task_create", ok=True, task_id=result["task"]["task_id"], data=result)

    def task_status(self, args: dict[str, Any]) -> dict[str, Any]:
        task_id = str(args["task_id"])
        return envelope("ctf_task_status", ok=True, task_id=task_id, data=self.tasks.get(task_id))

    def task_update(self, args: dict[str, Any]) -> dict[str, Any]:
        task_id = str(args["task_id"])
        result = self.tasks.update_workflow(
            task_id,
            phase=args.get("phase"),
            challenge_type=args.get("challenge_type"),
            primary_hypothesis=args.get("primary_hypothesis"),
            fallback_hypothesis=args.get("fallback_hypothesis"),
            next_actions=args.get("next_actions"),
            unresolved=args.get("unresolved"),
            progress_note=args.get("progress_note"),
        )
        return envelope("ctf_task_update", ok=True, task_id=task_id, data=result)

    def catalog(self, args: dict[str, Any]) -> dict[str, Any]:
        del args
        return envelope("ctf_tool_catalog", ok=True, data=tool_status(self.root))

    def file_inspect(self, args: dict[str, Any]) -> dict[str, Any]:
        return inspect_file(
            self.tasks,
            str(args["task_id"]),
            str(args["file"]),
            max_strings=int(args.get("max_strings", 80)),
        )

    def image_inspect(self, args: dict[str, Any]) -> dict[str, Any]:
        return inspect_image(self.tasks, str(args["task_id"]), str(args["file"]))

    def http_request(self, args: dict[str, Any]) -> dict[str, Any]:
        return perform_request(
            self.tasks,
            str(args["task_id"]),
            str(args["url"]),
            method=str(args.get("method", "GET")),
            headers=args.get("headers"),
            body=args.get("body"),
            timeout_seconds=float(args.get("timeout_seconds", 15)),
            max_response_bytes=int(args.get("max_response_bytes", 2 * 1024 * 1024)),
            follow_redirects=bool(args.get("follow_redirects", False)),
            insecure_tls=bool(args.get("insecure_tls", False)),
        )

    def pcap_analyze(self, args: dict[str, Any]) -> dict[str, Any]:
        return analyze_pcap(
            self.tasks,
            str(args["task_id"]),
            str(args["file"]),
            display_filter=args.get("display_filter"),
            timeout_seconds=int(args.get("timeout_seconds", 60)),
        )

    def auto_decode(self, args: dict[str, Any]) -> dict[str, Any]:
        return auto_decode(
            self.tasks,
            str(args["task_id"]),
            str(args["file"]),
            operations=args.get("operations"),
            xor_key=args.get("xor_key"),
            max_depth=int(args.get("max_depth", 4)),
        )

    def archive_inspect(self, args: dict[str, Any]) -> dict[str, Any]:
        return archive_inspect(
            self.tasks,
            str(args["task_id"]),
            str(args["file"]),
            extract=bool(args.get("extract", False)),
        )

    def reverse_static(self, args: dict[str, Any]) -> dict[str, Any]:
        return reverse_static(
            self.tasks,
            str(args["task_id"]),
            str(args["file"]),
        )

    def flag_candidate(self, args: dict[str, Any]) -> dict[str, Any]:
        return add_candidate(
            self.tasks,
            str(args["task_id"]),
            str(args["candidate"]),
            source=str(args["source"]),
            evidence_file=args.get("evidence_file"),
        )

    def flag_verify(self, args: dict[str, Any]) -> dict[str, Any]:
        return verify_flag(
            self.tasks,
            str(args["task_id"]),
            str(args["candidate"]),
            expected_regex=args.get("expected_regex"),
            evidence_file=args.get("evidence_file"),
        )

    def flag_scan(self, args: dict[str, Any]) -> dict[str, Any]:
        return scan_flags(
            self.tasks,
            str(args["task_id"]),
            evidence_file=str(args["evidence_file"]),
            patterns=args.get("patterns"),
            max_bytes=int(args.get("max_bytes", 8 * 1024 * 1024)),
        )

    def flag_submit(self, args: dict[str, Any]) -> dict[str, Any]:
        return submit_flag(
            self.tasks,
            str(args["task_id"]),
            candidate=str(args["candidate"]),
            submission_url=str(args["submission_url"]),
            expected_success_regex=str(args["expected_success_regex"]),
            method=str(args.get("method", "POST")),
            headers=args.get("headers"),
            body_template=str(args.get("body_template", '{"flag":"{{flag_json}}" }')),
            timeout_seconds=float(args.get("timeout_seconds", 15.0)),
        )

    def evidence_record(self, args: dict[str, Any]) -> dict[str, Any]:
        return record_action(
            self.tasks,
            str(args["task_id"]),
            description=str(args["description"]),
            command=args["command"],
            cwd=str(args.get("cwd", "")),
            exit_code=args.get("exit_code"),
            duration_ms=int(args.get("duration_ms", 0)),
            stdout=str(args.get("stdout", "")),
            stderr=str(args.get("stderr", "")),
            truncated=bool(args.get("truncated", False)),
            artifact_files=args.get("artifact_files"),
        )

    def register_artifact(self, args: dict[str, Any]) -> dict[str, Any]:
        return register_evidence_artifact(
            self.tasks,
            str(args["task_id"]),
            artifact_file=str(args["artifact_file"]),
            kind=str(args.get("kind", "file")),
        )

    def remote_exec(self, args: dict[str, Any]) -> dict[str, Any]:
        return execute_ssh(
            self.tasks,
            str(args["task_id"]),
            host=str(args["host"]),
            username=str(args["username"]),
            command=str(args["command"]),
            port=int(args.get("port", 22)),
            identity_file=args.get("identity_file"),
            known_hosts_file=args.get("known_hosts_file"),
            timeout_seconds=int(args.get("timeout_seconds", 60)),
            destructive_confirmed=bool(args.get("destructive_confirmed", False)),
        )

    def remote_http(self, args: dict[str, Any]) -> dict[str, Any]:
        return execute_remote_http(
            self.tasks,
            str(args["task_id"]),
            ssh_host=str(args["ssh_host"]),
            ssh_username=str(args["ssh_username"]),
            ssh_port=int(args["ssh_port"]),
            target_url=str(args["target_url"]),
            method=str(args.get("method", "GET")),
            headers=args.get("headers"),
            body=args.get("body"),
            identity_file=args.get("identity_file"),
            known_hosts_file=args.get("known_hosts_file"),
            timeout_seconds=int(args.get("timeout_seconds", 60)),
        )

    def validate_juice_admin(self, args: dict[str, Any]) -> dict[str, Any]:
        return validate_juice_shop_admin(
            self.tasks,
            str(args["task_id"]),
            str(args["token"]),
        )

    def report_write(self, args: dict[str, Any]) -> dict[str, Any]:
        return write_report(
            self.tasks,
            str(args["task_id"]),
            challenge_type=str(args.get("challenge_type", "unknown")),
            summary=str(args.get("summary", "")),
            unresolved=args.get("unresolved"),
        )

    def sandbox_status(self, args: dict[str, Any]) -> dict[str, Any]:
        del args
        return broker_status(self.tasks)

    def sandbox_build(self, args: dict[str, Any]) -> dict[str, Any]:
        return broker_build(
            self.tasks,
            str(args["profile"]),
            int(args.get("timeout_seconds", 1800)),
        )

    def sandbox_create(self, args: dict[str, Any]) -> dict[str, Any]:
        return broker_create(self.tasks, str(args["task_id"]), str(args["profile"]))

    def sandbox_exec(self, args: dict[str, Any]) -> dict[str, Any]:
        return broker_execute(
            self.tasks,
            str(args["task_id"]),
            str(args["container_id"]),
            str(args["command"]),
            timeout_seconds=int(args.get("timeout_seconds", 60)),
        )

    def sandbox_stop(self, args: dict[str, Any]) -> dict[str, Any]:
        return broker_stop(
            self.tasks,
            str(args["task_id"]),
            str(args["container_id"]),
        )

    def lab_build(self, args: dict[str, Any]) -> dict[str, Any]:
        return local_lab.build(
            self.tasks,
            str(args["lab"]),
            int(args.get("timeout_seconds", 1800)),
        )

    def lab_start(self, args: dict[str, Any]) -> dict[str, Any]:
        return local_lab.start(
            self.tasks,
            str(args["lab"]),
            int(args.get("host_port", 3000)),
        )

    def lab_stop(self, args: dict[str, Any]) -> dict[str, Any]:
        return local_lab.stop(self.tasks, str(args["lab"]))

    def lab_status(self, args: dict[str, Any]) -> dict[str, Any]:
        return local_lab.status(self.tasks, str(args["lab"]))

    def doctor(self, args: dict[str, Any]) -> dict[str, Any]:
        del args
        status = tool_status(self.root)
        return envelope(
            "ctf_doctor",
            ok=True,
            data={
                "python": sys.version,
                "executable": sys.executable,
                "project_root": str(self.root),
                "node": shutil.which("node"),
                "codex": shutil.which("codex.cmd") or shutil.which("codex"),
                "tshark": find_tshark(),
                "catalog": {
                    "detected": status["detected_count"],
                    "total": status["total_count"],
                },
                "docker_broker_configured": bool(os.environ.get("CTF_DOCKER_BROKER_URL")),
            },
        )


def mcp_tool_result(result: dict[str, Any]) -> dict[str, Any]:
    text = json.dumps(result, ensure_ascii=False, indent=2, default=str)
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": result,
        "isError": not bool(result.get("ok")),
    }
