param(
    [int]$Port = 8765
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$starter = Join-Path $PSScriptRoot "start-docker-broker.ps1"
$logs = Join-Path $root "logs"

if (-not (Test-Path -LiteralPath $starter)) {
    throw "Broker starter is missing: $starter"
}

New-Item -ItemType Directory -Path $logs -Force | Out-Null

$listenerLine = netstat -ano |
    Select-String -Pattern "127\.0\.0\.1:$Port\s+.*LISTENING\s+(\d+)$" |
    Select-Object -First 1

if ($listenerLine) {
    $listenerPid = [int](($listenerLine.ToString().Trim() -split "\s+")[-1])
    $process = Get-Process -Id $listenerPid -ErrorAction Stop
    if ($process.ProcessName -notmatch "^python") {
        throw "Refusing to stop non-Python process $listenerPid on port $Port"
    }
    Stop-Process -Id $listenerPid -Force
    Wait-Process -Id $listenerPid -ErrorAction SilentlyContinue
}

$stdout = Join-Path $logs "docker-broker.stdout.log"
$stderr = Join-Path $logs "docker-broker.stderr.log"
$arguments = @(
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    "`"$starter`"",
    "-Port",
    "$Port"
)

$child = Start-Process `
    -FilePath "powershell.exe" `
    -ArgumentList $arguments `
    -WorkingDirectory $root `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr `
    -PassThru

$deadline = (Get-Date).AddSeconds(20)
do {
    Start-Sleep -Milliseconds 250
    $listening = netstat -ano |
        Select-String -Pattern "127\.0\.0\.1:$Port\s+.*LISTENING\s+(\d+)$" |
        Select-Object -First 1
} while (-not $listening -and (Get-Date) -lt $deadline)

if (-not $listening) {
    throw "Broker did not start on 127.0.0.1:$Port. Check $stderr"
}

[pscustomobject]@{
    ok = $true
    launcher_pid = $child.Id
    broker_pid = [int](($listening.ToString().Trim() -split "\s+")[-1])
    port = $Port
    stdout = $stdout
    stderr = $stderr
} | ConvertTo-Json
