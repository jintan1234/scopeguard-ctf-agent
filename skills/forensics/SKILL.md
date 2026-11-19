---
name: ctf-forensics
description: Use for PCAP analysis, memory and disk images, deleted files, Windows event logs, browser artifacts, filesystem timelines, log analysis and YARA-style evidence extraction.
---

# Forensics

## Preserve originals

Work on copies. Record original hash and size. Do not mount or modify evidence images read-write.

## PCAP

1. `capinfos` and `tshark -z io,phs`.
2. Protocol hierarchy and conversations.
3. DNS, HTTP, TLS SNI, credentials, uploads/downloads.
4. Extract streams and objects into artifacts.
5. Reassemble files using hashes and magic, not extension.

Useful filters depend on the challenge:

- `http.request`
- `dns`
- `tls.handshake.extensions_server_name`
- `tcp.stream eq N`
- `frame contains "..."`

## Memory

1. Identify OS/profile.
2. List processes, connections, command lines, loaded modules.
3. Search process memory, clipboard, environment, browser state and credentials.
4. Dump only targeted regions/processes.

## Disk

1. Identify partition layout.
2. List files and alternate data.
3. Recover deleted entries/inodes.
4. Build a timeline from timestamps and logs.
5. Extract suspected flag artifact and preserve provenance.

## Windows artifacts

- Event logs
- Prefetch/AmCache/SRUM
- Registry hives
- Browser history/downloads
- PowerShell history
- Scheduled tasks/services

## Safety

Memory/disk images may contain private data. Search only for challenge-relevant artifacts and do not expose unrelated personal information in the report.

## Evidence

Record offsets, inode/process IDs, packet/stream IDs and extraction commands so another analyst can reproduce the finding.
