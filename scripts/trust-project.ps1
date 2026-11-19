param(
    [switch]$Confirm
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$configPath = Join-Path $env:USERPROFILE ".codex\config.toml"
$sections = @(
    "[projects.'$($root.ToLower())']"
)

if (-not (Test-Path -LiteralPath $configPath)) {
    throw "Codex config not found: $configPath"
}

$text = [System.IO.File]::ReadAllText($configPath)
$missing = @($sections | Where-Object { $text -notmatch [regex]::Escape($_) })

if (-not $Confirm) {
    Write-Host "Dry run only."
    Write-Host "Config: $configPath"
    Write-Host "Sections to append:"
    $missing | ForEach-Object { Write-Host "  $_`n  trust_level = `"trusted`"" }
    Write-Host "Run with -Confirm to back up and apply."
    exit 0
}

if ($missing.Count -eq 0) {
    Write-Host "Project trust entries already exist; no changes made."
    exit 0
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backup = "$configPath.backup-$stamp"
Copy-Item -LiteralPath $configPath -Destination $backup

$append = "`r`n"
foreach ($section in $missing) {
    $append += "$section`r`ntrust_level = `"trusted`"`r`n`r`n"
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($configPath, $text.TrimEnd() + $append, $utf8NoBom)

Write-Host "Backup: $backup"
Write-Host "Added project trust entries:"
$missing | ForEach-Object { Write-Host "  $_" }
