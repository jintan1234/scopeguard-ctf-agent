param(
    [string]$TaskId
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $root ".venv\Scripts\python.exe"
$env:PYTHONPATH = Join-Path $root "tools"

if (-not $TaskId) {
    $scopePath = Join-Path $root "challenges\current\active-scope.json"
    if (-not (Test-Path -LiteralPath $scopePath)) {
        throw "No active task scope. Pass -TaskId explicitly."
    }
    $TaskId = (Get-Content -Raw -LiteralPath $scopePath | ConvertFrom-Json).task_id
}

$probes = [ordered]@{
    analysis = "tests\fixtures\sandbox_probe.sh"
    pwn = "tests\fixtures\pwn_probe.sh"
    web = "tests\fixtures\expanded_web_probe.sh"
    reverse = "tests\fixtures\expanded_reverse_probe.sh"
    remote = "tests\fixtures\expanded_remote_probe.sh"
    crypto = "tests\fixtures\expanded_crypto_probe.sh"
}

$results = @()
foreach ($entry in $probes.GetEnumerator()) {
    $profile = $entry.Key
    $probe = Join-Path $root $entry.Value
    $created = & $python -m ctf_core.cli sandbox-create `
        --task-id $TaskId `
        --profile $profile | ConvertFrom-Json
    if (-not $created.ok) {
        $results += [pscustomobject]@{
            profile = $profile
            create_ok = $false
            error = $created.error.message
        }
        continue
    }

    $container = $created.data.container_id
    try {
        $executed = & $python -m ctf_core.cli sandbox-exec `
            --task-id $TaskId `
            --container-id $container `
            --command-file $probe `
            --timeout 120 | ConvertFrom-Json
        $results += [pscustomobject]@{
            profile = $profile
            create_ok = $true
            exec_ok = $executed.ok
            exit_code = $executed.exit_code
            stdout = $executed.data.stdout
            stderr = $executed.data.stderr
        }
    } finally {
        & $python -m ctf_core.cli sandbox-stop `
            --task-id $TaskId `
            --container-id $container | Out-Null
    }
}

$output = Join-Path $root "logs\toolchain-check.json"
$results | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $output -Encoding UTF8
$results | Select-Object profile,create_ok,exec_ok,exit_code | Format-Table -AutoSize

if ($results.Where({ -not $_.create_ok -or -not $_.exec_ok }).Count -gt 0) {
    throw "One or more profiles failed. See $output"
}

Write-Host "All profiles passed. Evidence: $output"
