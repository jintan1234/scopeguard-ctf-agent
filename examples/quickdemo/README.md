# Offline quick demo

This demo runs the complete workflow against a local synthetic Crypto fixture:

1. create an authorized task;
2. copy the encoded fixture;
3. run the auto-decoder;
4. register a Flag candidate;
5. verify it against the saved decode artifact;
6. generate `report.md` and `result.json`.

It uses a temporary directory and makes no network requests.

```bash
python examples/quickdemo/demo.py
```

The temporary task is removed when the process exits.
