param(
    [switch]$Confirm
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$configDir = Join-Path $root ".codex"
$configPath = Join-Path $configDir "config.toml"
$sourcePath = Join-Path $root "config\codex-mcp.project.toml.example"

if (-not (Test-Path -LiteralPath $sourcePath)) {
    throw "MCP configuration template is missing: $sourcePath"
}

if (-not $Confirm) {
    Write-Host "Dry run only. This would create or update:"
    Write-Host "  $configPath"
    Write-Host "from:"
    Write-Host "  $sourcePath"
    Write-Host "Run with -Confirm after reviewing the project MCP snippet."
    exit 0
}

if (Test-Path -LiteralPath $configPath) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backup = "$configPath.backup-$stamp"
    Copy-Item -LiteralPath $configPath -Destination $backup
    Write-Host "Backed up project config to $backup"
}

New-Item -ItemType Directory -Force -Path $configDir | Out-Null
$template = [System.IO.File]::ReadAllText($sourcePath)
$tomlRoot = $root.Replace('\', '\\')
$template = $template.Replace("<PROJECT_ROOT>", $tomlRoot)
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($configPath, $template, $utf8NoBom)
Write-Host "Installed project-scoped MCP configuration: $configPath"
Write-Host "Start a new Codex thread in this project so the MCP servers are loaded."
