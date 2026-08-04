# Independent repro: full unit suite (no Discord token, no network services).
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
python -m pip install -e ".[dev]" -q
python -m pytest -q
Write-Output "REPRO_OK agentic-dm-gateway unit suite"
