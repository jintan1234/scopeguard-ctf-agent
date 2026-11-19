# Case studies

The public case studies preserve historical internal-lab targets and verified
results:

- real internal CTF lab IPs and ports are retained;
- verified Flags are retained;
- attack payloads, failure paths and corrections are retained;
- personal platform credentials and local machine paths are excluded;
- the historical labs may be offline or reassigned, so the addresses are
  evidence records rather than permission to test them.

Included studies:

1. `fruit-ret2libc`: a two-stage ret2libc exploit with leak parsing, remote
   libc matching, stack alignment and shell validation.
2. `easy-dex`: Android Native loader, XOR-zlib protected DEX, JADX analysis and
   Twofish round-trip verification.
3. `go-vm`: a stripped Go binary containing a custom integer stack VM and a
   symbolic-execution solver.
4. `sql-injection-cves`: authenticated ORDER BY injection and Django ORM alias
   injection, with reproducible scripts and explicit negative outcomes.
5. `sqli-labs-less1`: a UNION SQL injection with a verified Flag.
6. `easyida`: a Windows PE reverse-engineering case with Unicorn emulation.
7. `crypto-base64-xor`: a bounded Base64 plus XOR decoding case.
8. `misc-fake-zip`: a fake-encryption ZIP case.

The historical archive did not contain a complete, valuable real Forensics or
OSINT challenge result. No synthetic case is presented as a completed real
forensics solve.
