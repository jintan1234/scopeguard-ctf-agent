$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = if ($env:CTF_PYTHON) {
    $env:CTF_PYTHON
} elseif (Test-Path -LiteralPath (Join-Path $root ".venv\Scripts\python.exe")) {
    Join-Path $root ".venv\Scripts\python.exe"
} else {
    (Get-Command python -ErrorAction Stop).Source
}
$env:PYTHONPATH = Join-Path $root "tools"
Push-Location $root
try {
    & $python -m unittest discover -s tests -v
} finally {
    Pop-Location
}
