$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = if ($env:CTF_PYTHON) {
    $env:CTF_PYTHON
} elseif (Test-Path -LiteralPath (Join-Path $root ".venv\Scripts\python.exe")) {
    Join-Path $root ".venv\Scripts\python.exe"
} else {
    (Get-Command python -ErrorAction Stop).Source
}

[pscustomobject]@{
    ProjectRoot = $root
    PythonPath = $python
    PythonExists = Test-Path -LiteralPath $python
    PowerShell = $PSVersionTable.PSVersion.ToString()
    Node = if (Get-Command node -ErrorAction SilentlyContinue) { (node --version) } else { "" }
    Codex = if (Test-Path -LiteralPath "$env:APPDATA\npm\codex.cmd") { (& "$env:APPDATA\npm\codex.cmd" --version) } else { "" }
    Tshark = if (Test-Path -LiteralPath "C:\Program Files\Wireshark\tshark.exe") { "C:\Program Files\Wireshark\tshark.exe" } else { "" }
    BrokerConfigured = [bool]$env:CTF_DOCKER_BROKER_URL
} | Format-List

if (-not (Test-Path -LiteralPath $python)) {
    throw "CTF Python was not found. Set CTF_PYTHON to the real python.exe path."
}

$env:PYTHONPATH = Join-Path $root "tools"
& $python -m ctf_core.cli tool-catalog
