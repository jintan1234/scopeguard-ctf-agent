# Case study: Base64 plus single-byte XOR

This case is the historical offline Crypto validation challenge included in
the original workspace.

```text
Target: local encoded text file
Flag: FLAG{CRYPTO_BASE64_XOR_LOCAL_TEST}
Assurance: reproducible_evidence
```

## Approach

1. Run a bounded auto-decoder.
2. Decode the outer Base64 layer.
3. Enumerate single-byte XOR keys.
4. Rank candidates by printable-text score and Flag-pattern matches.
5. Save all candidates as an artifact.

## Script

```bash
PYTHONPATH=tools python solve.py path/to/crypto-chain.txt
```

The script uses the project's scoped task and evidence APIs and does not make
network requests.
