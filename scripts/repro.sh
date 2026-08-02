#!/usr/bin/env bash
# Independent repro: full unit suite (no Discord token, no network services).
set -euo pipefail
cd "$(dirname "$0")/.."
python -m pip install -e ".[dev]" -q
python -m pytest -q
echo "REPRO_OK agentic-dm-gateway unit suite"
