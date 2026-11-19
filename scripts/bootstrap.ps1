param(
    [switch]$ConfigureCodex,
    [switch]$TrustProject,
    [switch]$BuildAnalysis,
    [switch]$SkipBrowser
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location -LiteralPath $root

function Assert-LastExit([string]$Message) {
    if ($LASTEXITCODE -ne 0) {
        throw $Message
    }
}

Write-Host "== ScopeGuard bootstrap =="
Write-Host "Root: $root"

$venvPython = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $venvPython)) {
    if ($env:CTF_PYTHON -and (Test-Path -LiteralPath $env:CTF_PYTHON)) {
        & $env:CTF_PYTHON -m venv (Join-Path $root ".venv")
        Assert-LastExit "Failed to create Python virtual environment from CTF_PYTHON."
    } else {
        $launcher = Get-Command py -ErrorAction SilentlyContinue
        if ($launcher) {
            & $launcher.Source -3.12 -m venv (Join-Path $root ".venv")
            if ($LASTEXITCODE -ne 0) {
                & $launcher.Source -3 -m venv (Join-Path $root ".venv")
            }
        } else {
            $python = Get-Command python -ErrorAction Stop
            & $python.Source -m venv (Join-Path $root ".venv")
        }
        Assert-LastExit "Failed to create Python virtual environment."
    }
}

& $venvPython -m pip install --upgrade pip setuptools wheel
Assert-LastExit "Failed to update pip."

& $venvPython -m pip install -r (Join-Path $root "requirements-core.txt")
Assert-LastExit "Failed to install Python analysis dependencies."

& $venvPython -m pip install -e $root
Assert-LastExit "Failed to install ScopeGuard package."

if (-not $SkipBrowser) {
    $npm = Get-Command npm.cmd -ErrorAction Stop
    $npx = Get-Command npx.cmd -ErrorAction Stop
    $playwrightRoot = Join-Path $root "mcp\playwright"
    $browserCache = Join-Path $playwrightRoot "browsers"
    New-Item -ItemType Directory -Path $browserCache -Force | Out-Null
    Push-Location -LiteralPath $playwrightRoot
    try {
        & $npm.Source ci
        Assert-LastExit "npm ci failed."
        $env:PLAYWRIGHT_BROWSERS_PATH = $browserCache
        & $npx.Source playwright install chromium
        Assert-LastExit "Playwright Chromium installation failed."
    } finally {
        Pop-Location
    }
}

New-Item -ItemType Directory -Path (Join-Path $root "challenges\current") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $root "logs") -Force | Out-Null

if ($ConfigureCodex) {
    powershell -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $root "scripts\enable-codex-mcp.ps1") -Confirm
    Assert-LastExit "Failed to configure project-scoped Codex MCP."
}

if ($TrustProject) {
    powershell -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $root "scripts\trust-project.ps1") -Confirm
    Assert-LastExit "Failed to configure Codex project trust."
}

$env:CTF_PYTHON = $venvPython
$env:PYTHONPATH = Join-Path $root "tools"
$env:PYTHONDONTWRITEBYTECODE = "1"

& $venvPython -m unittest discover -s (Join-Path $root "tests") -v
Assert-LastExit "Unit tests failed."

& $venvPython (Join-Path $root "examples\quickdemo\demo.py")
Assert-LastExit "Offline demo failed."

if ($BuildAnalysis) {
    docker build `
        -t ctf-agent/analysis:0.2 `
        -f (Join-Path $root "docker\analysis\Dockerfile") `
        (Join-Path $root "docker\analysis")
    Assert-LastExit "Analysis Docker build failed."
}

Write-Host ""
Write-Host "Bootstrap complete."
if (-not $ConfigureCodex) {
    Write-Host "Configure Codex MCP with:"
    Write-Host "  powershell -ExecutionPolicy Bypass -File .\scripts\enable-codex-mcp.ps1 -Confirm"
}
Write-Host "Start the Docker broker in a second terminal:"
Write-Host "  powershell -ExecutionPolicy Bypass -File .\scripts\start-docker-broker.ps1"
Write-Host "Then start Codex from this directory:"
Write-Host "  codex"
