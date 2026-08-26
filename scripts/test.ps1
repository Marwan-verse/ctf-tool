[CmdletBinding()]
param(
    [switch]$NoInstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workspace = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $workspace 'backend'
$venv = Join-Path $backend '.venv'
$python = Join-Path $venv 'Scripts\python.exe'

if (-not (Test-Path -LiteralPath $python)) {
    python -m venv $venv
}

Push-Location $backend
try {
    if (-not $NoInstall) {
        & $python -m pip install --upgrade pip
        & $python -m pip install -e '.[dev]'
    }
    & $python -m pytest @args
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
