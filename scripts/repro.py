"""Independent offline repro for agentic-dm-gateway."""
from __future__ import annotations
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def main() -> int:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-e", ".[dev]", "-q"], cwd=ROOT)
    r = subprocess.call([sys.executable, "-m", "pytest", "-q"], cwd=ROOT)
    if r == 0:
        print("REPRO_OK agentic-dm-gateway unit suite")
    return r

if __name__ == "__main__":
    raise SystemExit(main())
