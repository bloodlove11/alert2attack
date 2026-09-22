#!/usr/bin/env bash
# QLoRA SFT on Lightning GPU. Does not change eval metrics.
# Train deps: `uv sync --group train` (see docs/TRAIN.md). Do not pip-install unpinned unsloth.
# Paths: ALERT2ATTACK_STUDIO_ROOT, ALERT2ATTACK_EXP_DIR (alias EXP004_ROOT). ALERT2ATTACK_PRINT_PATHS=1 exits after printing.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lightning_paths.sh
source "${SCRIPT_DIR}/lightning_paths.sh"
ALERT2ATTACK_EXP_DIR="${ALERT2ATTACK_EXP_DIR:-${EXP004_ROOT:-${ALERT2ATTACK_STUDIO_ROOT}/exp004-n14}}"
if lightning_maybe_print_paths; then
  exit 0
fi
ROOT="${ALERT2ATTACK_EXP_DIR}"
cd "$ROOT"
PY="${PYTHON:-/home/zeus/miniconda3/envs/cloudspace/bin/python}"
mkdir -p artifacts/qlora-n14
if ! "$PY" -c "import unsloth, datasets, trl"; then
  echo "Missing train deps in ${PY}." >&2
  echo "From the alert2attack checkout: uv sync --group train" >&2
  echo "Then rerun with PYTHON pointing at that venv, e.g. PYTHON=.venv/bin/python $0" >&2
  exit 1
fi
export PYTHONUNBUFFERED=1
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
"$PY" scripts/train_qlora_sft.py \
  --sft-jsonl data/sft-lever5-n14.jsonl \
  --out artifacts/qlora-n14 \
  --max-seq-length 2048
echo "TRAIN_EXIT:$? $(date -u +%FT%TZ)"
