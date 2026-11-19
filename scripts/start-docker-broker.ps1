param(
    [int]$Port = 8765,
    [switch]$BuildAnalysis
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    throw "Project Python venv is missing: $python"
}

$env:CTF_DOCKER_BROKER_URL = "http://127.0.0.1:$Port"
Write-Host "Starting restricted Docker broker on 127.0.0.1:$Port"
Write-Host "Keep this terminal open. Press Ctrl+C to stop."

if ($BuildAnalysis) {
    $job = Start-Job -ScriptBlock {
        param($broker, $root, $port)
        Start-Sleep -Seconds 2
        $env:PYTHONPATH = Join-Path $root "tools"
        & $broker -m ctf_core.cli sandbox-build --profile analysis --timeout 1800
    } -ArgumentList $python, $root, $Port
    Write-Host "Analysis image build job started: $($job.Id)"
}

& $python (Join-Path $root "mcp\docker-broker\broker.py") --root $root --host 127.0.0.1 --port $Port
