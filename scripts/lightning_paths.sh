# Shared Lightning Studio path defaults. Source from scripts/lightning_*.sh.
# Does not train, eval, or download models.
#
#   ALERT2ATTACK_STUDIO_ROOT  Studio root
#   ALERT2ATTACK_EVAL_DIR     alert2attack checkout used for uv sync + eval
#   ALERT2ATTACK_EXP_DIR      experiment working dir (set by each caller if unset)
#
# ALERT2ATTACK_PRINT_PATHS=1 prints resolved paths; callers should then exit 0.

: "${ALERT2ATTACK_STUDIO_ROOT:=/teamspace/studios/this_studio}"
: "${ALERT2ATTACK_EVAL_DIR:=${ALERT2ATTACK_STUDIO_ROOT}/alert2attack-lever6}"

lightning_export_local_path() {
  export PATH="${HOME}/.local/bin:${ALERT2ATTACK_STUDIO_ROOT}/.local/bin:${PATH:-}"
}

lightning_maybe_print_paths() {
  if [[ "${ALERT2ATTACK_PRINT_PATHS:-}" != "1" ]]; then
    return 1
  fi
  echo "ALERT2ATTACK_STUDIO_ROOT=${ALERT2ATTACK_STUDIO_ROOT}"
  echo "ALERT2ATTACK_EVAL_DIR=${ALERT2ATTACK_EVAL_DIR}"
  echo "ALERT2ATTACK_EXP_DIR=${ALERT2ATTACK_EXP_DIR:-}"
  return 0
}
