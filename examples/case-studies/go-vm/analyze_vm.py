#!/usr/bin/env python3
"""Decode and symbolically execute a simple integer stack VM."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

import sympy as sp


VM_BASE = 0x400000
CODE_VA = 0x564D20
CODE_COUNT = 298
TARGET_VA = 0x4EEE60
TARGET_COUNT = 72


def int64_words(path: Path, va: int, count: int) -> list[int]:
    data = path.read_bytes()
    offset = va - VM_BASE
    return list(struct.unpack_from(f"<{count}q", data, offset))


def render(code: list[int]) -> list[str]:
    output: list[str] = []
    pc = 0
    names = {
        0: "STOP",
        1: "PRINT",
        2: "NEG",
        3: "ADD",
        4: "MUL",
        7: "INPUT",
        8: "CHECK",
        9: "SET",
    }
    while pc < len(code):
        op = code[pc]
        if op == 5:
            output.append(f"{pc:03d}: PUSH {code[pc + 1]}")
            pc += 2
            continue
        output.append(f"{pc:03d}: {names.get(op, f'UNKNOWN_{op}')}")
        pc += 1
    return output


def symbolic_execute(code: list[int], target: list[int]) -> list[dict]:
    stack: list[sp.Expr] = []
    input_index = 0
    checks: list[list[sp.Expr]] = []
    pc = 0

    while pc < len(code):
        op = code[pc]
        if op == 0:
            break
        if op == 1:
            stack.pop()
        elif op == 2:
            stack[-1] = -stack[-1]
        elif op in (3, 4):
            right = stack.pop()
            left = stack.pop()
            stack.append(left + right if op == 3 else left * right)
        elif op == 5:
            stack.append(sp.Integer(code[pc + 1]))
            pc += 1
        elif op == 7:
            stack.append(sp.Symbol(f"x{input_index}", integer=True))
            input_index += 1
        elif op == 8:
            checks.append(list(stack))
        elif op == 9:
            index = stack.pop()
            value = stack.pop()
            if index.is_Integer is not True:
                raise ValueError(f"non-constant SET index at {pc}")
            stack[int(index)] = value
        else:
            raise ValueError(f"unknown opcode {op} at {pc}")
        pc += 1

    equations = []
    for snapshot in checks:
        equations.extend(
            sp.Eq(expression, sp.Integer(expected))
            for expression, expected in zip(snapshot, target)
        )

    unknowns = sp.symbols(f"x0:{input_index}", integer=True)
    solution = sp.solve(list(dict.fromkeys(equations)), unknowns, dict=True)
    return solution


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--render-output", type=Path)
    parser.add_argument("--execution-output", type=Path)
    args = parser.parse_args()

    code = int64_words(args.binary, CODE_VA, CODE_COUNT)
    target = int64_words(args.binary, TARGET_VA, TARGET_COUNT)

    rendered = "\n".join(render(code)) + "\n"
    print(rendered, end="")
    if args.render_output:
        args.render_output.write_text(rendered, encoding="utf-8")

    solution = symbolic_execute(code, target)
    text = repr(solution) + "\n"
    print(text, end="")
    if args.execution_output:
        args.execution_output.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
