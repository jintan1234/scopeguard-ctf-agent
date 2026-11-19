$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$errors = [System.Collections.Generic.List[string]]::new()

$forbiddenDirectories = @(
    ".venv",
    ".cache",
    "tool-runtime",
    "third_party",
    "challenges",
    "logs"
)

foreach ($name in $forbiddenDirectories) {
    if (Test-Path -LiteralPath (Join-Path $root $name)) {
        $errors.Add("Forbidden runtime directory exists: $name")
    }
}

if (Test-Path -LiteralPath (Join-Path $root "config\docker-broker-token")) {
    $errors.Add("Broker token must not be committed.")
}

$denylistPath = Join-Path $root "config\private-denylist.txt"
if (Test-Path -LiteralPath $denylistPath) {
    $textFiles = Get-ChildItem -LiteralPath $root -File -Recurse |
        Where-Object {
            $_.FullName -notmatch '\\\.git\\' -and
            $_.FullName -ne $denylistPath
        }
    foreach ($marker in Get-Content -LiteralPath $denylistPath -Encoding UTF8) {
        $marker = $marker.Trim()
        if (-not $marker -or $marker.StartsWith("#")) {
            continue
        }
        $hits = $textFiles | Select-String -SimpleMatch -Pattern $marker
        if ($hits) {
            $errors.Add("Private marker found in public tree: $($hits.Path -join ', ')")
        }
    }
}

$forbiddenExtensions = @(".apk", ".rar", ".exe", ".7z")
$largeFiles = Get-ChildItem -LiteralPath $root -File -Recurse |
    Where-Object {
        $_.Length -gt 20MB -or
        ($_.DirectoryName -eq $root -and $_.Extension -in $forbiddenExtensions)
    }
foreach ($file in $largeFiles) {
    $errors.Add("Unexpected large or attachment-like file: $($file.FullName)")
}

$required = @(
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "pyproject.toml",
    "tools\ctf_core\mcp_server.py",
    "tests\test_scope.py",
    "examples\case-studies\fruit-ret2libc\exp.py",
    "examples\case-studies\easy-dex\recover_easy_dex.py",
    "examples\case-studies\go-vm\analyze_vm.py",
    "examples\case-studies\sql-injection-cves\django_alias_union.py"
)
foreach ($relative in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $relative))) {
        $errors.Add("Required file is missing: $relative")
    }
}

$licenseFiles = @(
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
    "licenses\BinaryPilot-Apache-2.0.txt",
    "licenses\Heimdall-MIT.txt",
    "licenses\Veria-Labs-CTF-Agent-MIT.txt",
    "licenses\Hybrid-Computer-Use-MIT.txt",
    "licenses\CLI-Anything-Apache-2.0.txt",
    "licenses\Playwright-MCP-Apache-2.0.txt",
    "licenses\StegSeek-GPL-2.0.txt",
    "licenses\REFERENCE-Conly-Zy-Pojun-AGPL-3.0.txt",
    "docs\upstream\CONLY_CTF_AGENT_AUDIT.md",
    "docs\upstream\SOURCE-MAP.md",
    "docs\upstream\LICENSE-PROVENANCE.md"
)
foreach ($relative in $licenseFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $relative))) {
        $errors.Add("Third-party attribution file is missing: $relative")
    }
}

$readme = Get-Content -Raw -LiteralPath (Join-Path $root "README.md")
if (
    $readme -notmatch [regex]::Escape(
        "https://github.com/Conly-Zy/CTF-Agent"
    ) -or
    $readme -notmatch "license could not be independently verified"
) {
    $errors.Add("Conly-Zy/CTF-Agent acknowledgement or UNKNOWN-license note is missing.")
}

$notices = Get-Content -Raw -LiteralPath (Join-Path $root "THIRD_PARTY_NOTICES.md")
if (
    $notices -notmatch "Conly-Zy/CTF-Agent" -or
    $notices -notmatch "License:\s+UNKNOWN"
) {
    $errors.Add("Conly-Zy/CTF-Agent UNKNOWN-license provenance is missing.")
}

$scopeAllowed = Get-Content -Raw -LiteralPath (Join-Path $root "config\scope.schema.json")
if (-not $scopeAllowed) {
    $errors.Add("Scope schema is empty.")
}

if ($errors.Count -gt 0) {
    $errors | ForEach-Object { Write-Error $_ }
    exit 1
}

$files = Get-ChildItem -LiteralPath $root -File -Recurse |
    Where-Object {
        $_.FullName -notmatch '\\\.git\\' -and
        $_.Name -ne "private-denylist.txt"
    }
$size = ($files | Measure-Object Length -Sum).Sum

[pscustomobject]@{
    ok = $true
    root = $root
    files = $files.Count
    size_mb = [math]::Round($size / 1MB, 2)
    git_repository = Test-Path -LiteralPath (Join-Path $root ".git")
} | Format-List
