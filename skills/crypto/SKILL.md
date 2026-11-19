---
name: ctf-crypto
description: Use for CTF encoding chains, classical ciphers, RSA, AES, ECC, hashes, weak randomness, XOR, Z3 constraints, lattices and other mathematical key-recovery challenges.
---

# Crypto

## Start with structure

1. Identify text/binary encoding.
2. Extract parameters and preserve exact values.
3. Determine whether the task provides ciphertext, oracle, public key, source, known plaintext or partial key.
4. Write down the assumed construction before coding.

## Classical / encoding

Try transformations with a reason. Record each chain step and intermediate output. Use frequency, known plaintext or challenge hints before exhaustive search.

## RSA

Check:

- small `e`, common modulus, shared primes;
- close `p`, `q`;
- leaked `d`, `dp`, `dq`, `qinv`;
- partial bits;
- Fermat/Hastad/Coppersmith conditions;
- faulty signatures or message padding;
- deterministic/biased nonces.

Use sympy/PyCryptodome first. Add RsaCtfTool only as an experiment matrix, not as the sole reasoning path.

## Symmetric crypto

- Determine mode, nonce/IV and padding.
- Check nonce reuse, ECB patterns, CBC bit-flipping, oracle behavior and key derivation.
- Verify decrypted plaintext structure.

## ECC

- Identify curve, subgroup and encoding.
- Check singular/anomalous curves, invalid points, nonce bias/reuse and small subgroup issues.
- Prefer lightweight scripts when SageMath is not needed.

## Z3 / constraints

Model only the relevant unknowns. Add constraints from source and observed outputs. If the solver is slow, reduce bit width, split the problem or follow the intended algebraic attack.

## Evidence

Save the exact parameters, solver script, intermediate outputs and final decrypted artifact. Re-run the recovery script before reporting the flag.
