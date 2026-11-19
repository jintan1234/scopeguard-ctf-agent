# Windows desktop MCP

## Existing desktop layer

The existing `windows-computer-use` MCP passed a UI Automation, screenshot and input health check during phase 1.

Status: available in the current Codex session; application-specific support is still unverified.

Use this layer only when a target application lacks an adequate CLI or API.

## Hybrid Computer Use

Source repository:

```text
<PROJECT_ROOT>\mcp\computer-use
```

Current status: not deployed.

The official Windows build requires Go 1.22+, .NET 8 SDK and PowerShell 7+. This machine has Go 1.26.4 and .NET SDK 10 with .NET 8 runtime, but no PowerShell 7.

A direct `dotnet publish` attempt was made without installing PowerShell 7. It entered NuGet restore for FlaUI/System.Drawing packages and made no progress within the bounded wait window. It was terminated and is not counted as a successful build.

## Decision

Do not deploy HCU merely to duplicate an already working desktop MCP.

Deploy it only if:

- application-specific tests show the existing MCP cannot read the necessary windows;
- AX batching/diff or HCU's target guards are materially useful;
- the user approves the PowerShell 7 and NuGet downloads.

For untrusted tasks, HCU must run on a disposable VM/desktop because its input is not isolated by the Codex shell sandbox.
