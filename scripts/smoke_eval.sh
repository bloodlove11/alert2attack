#!/usr/bin/env bash
# Offline eval smoke (plumbing). Live arms: pass --live local|teacher|b0
set -euo pipefail
cd "$(dirname "$0")/.."
exec uv run python scripts/smoke_eval.py "$@"
