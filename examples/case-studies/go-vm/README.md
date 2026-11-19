# Case study: custom VM inside a stripped Go binary

An authorized reverse-engineering challenge contained a stripped Go 1.15.2
x86-64 ELF.

```text
Target: offline local ELF
Flag: flag{I_am_the_last_one}
Assurance: reproducible_evidence
```

## Discovery

The binary contains:

- 298 int64 VM instruction words at `0x564D20`;
- 72 int64 target values at `0x4EEE60`.

## VM semantics

```text
0 STOP
1 PRINT
2 NEG
3 ADD
4 MUL
5 PUSH immediate
7 INPUT integer
8 CHECK
9 SET stack[index]
```

## Solution strategy

1. Decode the 298-word instruction stream.
2. Represent each `INPUT` as a symbolic integer.
3. Execute the VM symbolically.
4. Turn every CHECK snapshot into equations.
5. Solve the equations.
6. Convert integer inputs to ASCII.
7. Feed the integers back to the original binary.

The original binary printed `got it!`, providing a local validator for the
recovered input.

## Scripts

- [`analyze_vm.py`](analyze_vm.py): render and symbolically execute the VM.
- [`run_solution.py`](run_solution.py): run a recovered integer list against
  the original binary.

Example:

```bash
python analyze_vm.py challenge.bin \
  --render-output vm-program.txt \
  --execution-output vm-symbolic.txt

python run_solution.py challenge.bin solution.json
```

The recovered integer input is included in
[`solution.json`](solution.json).

The original challenge binary is Linux ELF. Run `run_solution.py` on Linux or
inside the analysis Docker profile when using Windows.
