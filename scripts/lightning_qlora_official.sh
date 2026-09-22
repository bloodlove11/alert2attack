#!/usr/bin/env bash
# Official QLoRA N=13 test eval on Lightning. Eval flags/model tag unchanged.
# Paths: ALERT2ATTACK_STUDIO_ROOT, ALERT2ATTACK_EVAL_DIR, ALERT2ATTACK_EXP_DIR. ALERT2ATTACK_PRINT_PATHS=1 exits after printing.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lightning_paths.sh
source "${SCRIPT_DIR}/lightning_paths.sh"
ALERT2ATTACK_EXP_DIR="${ALERT2ATTACK_EXP_DIR:-${ALERT2ATTACK_STUDIO_ROOT}/exp004-n14}"
if lightning_maybe_print_paths; then
  exit 0
fi
EVAL_DIR="${ALERT2ATTACK_EVAL_DIR}"
LOG="${ALERT2ATTACK_EXP_DIR}/official.log"
OUT="${ALERT2ATTACK_EXP_DIR}/official-test"

{
  echo "OFFICIAL_START $(date -u +%FT%TZ) timeout=${ALERT2ATTACK_LLM_TIMEOUT_S:-3600}"
  echo "ALERT2ATTACK_STUDIO_ROOT=${ALERT2ATTACK_STUDIO_ROOT}"
  echo "ALERT2ATTACK_EVAL_DIR=${ALERT2ATTACK_EVAL_DIR}"
  echo "ALERT2ATTACK_EXP_DIR=${ALERT2ATTACK_EXP_DIR}"
  nvidia-smi --query-gpu=name,memory.total,memory.used --format=csv,noheader
  export OLLAMA_KEEP_ALIVE=-1
  if ! command -v ollama >/dev/null 2>&1; then
    curl -fsSL https://ollama.com/install.sh | sh
  fi
  if ! curl -sf --max-time 5 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    nohup env OLLAMA_KEEP_ALIVE=-1 ollama serve >/tmp/ollama.log 2>&1 &
    echo $! >/tmp/ollama.pid
    for i in $(seq 1 40); do
      curl -sf --max-time 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && break
      sleep 1
    done
  fi
  test -f "$EVAL_DIR/src/alert2attack/agent/lsass_fp.py" || { echo "missing lever-6 eval tree"; exit 2; }
  ollama list
  ollama ps || true
  cd "$EVAL_DIR"
  lightning_export_local_path
  command -v uv >/dev/null || curl -LsSf https://astral.sh/uv/install.sh | sh
  uv sync --frozen
  export ALERT2ATTACK_OLLAMA_MODEL=casefile-qlora-n14
  export ALERT2ATTACK_LLM_TIMEOUT_S="${ALERT2ATTACK_LLM_TIMEOUT_S:-3600}"
  unset ALERT2ATTACK_OLLAMA_BASE_URL || true
  unset ALERT2ATTACK_TIMEOUT_S ALERT2ATTACK_MAX_INVESTIGATE_TURNS ALERT2ATTACK_MAX_TOOL_CALLS ALERT2ATTACK_MAX_LLM_CALLS || true
  export PYTHONUNBUFFERED=1
  mkdir -p "$OUT"
  uv run alert2attack eval run --arm agent-local-7b --split test --out "$OUT"
  echo "OFFICIAL_EXIT:$? $(date -u +%FT%TZ)"
  nvidia-smi --query-gpu=name,memory.used --format=csv,noheader
  ollama ps || true
} >>"$LOG" 2>&1
echo $? >"${ALERT2ATTACK_EXP_DIR}/official.exit"
