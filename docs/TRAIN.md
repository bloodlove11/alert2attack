# Train extras (optional)

QLoRA SFT deps are kept out of the default runtime (API Docker / `uv sync` / CI).
Lightning historically `pip install`ed `unsloth datasets trl` ad-hoc; the lock is the pin.

```bash
uv sync --group train
```

That group is what `scripts/train_qlora_sft.py` imports (`unsloth`, `datasets`, `trl`, plus
`torch` / `peft` / `bitsandbytes` / `transformers`). Never run `uv sync --group train` in CI
or on the API image: CUDA wheels are large, and CI must not download models or launch GPU jobs.

Eval / prepare JSONL stays on the default env:

```bash
uv run python scripts/prepare_sft_examples.py reports/distill/teacher-dev.filtered.jsonl --out reports/distill/sft.jsonl
```

## Lightning Studio paths

`scripts/lightning_*.sh` no longer hardcode a single Studio checkout. Override as needed:

| Variable | Default | Used for |
|---|---|---|
| `ALERT2ATTACK_STUDIO_ROOT` | `/teamspace/studios/this_studio` | Studio root, `PATH` `…/.local/bin` |
| `ALERT2ATTACK_EVAL_DIR` | `$ALERT2ATTACK_STUDIO_ROOT/alert2attack-lever6` | alert2attack tree for `uv sync` + `eval run` |
| `ALERT2ATTACK_EXP_DIR` | `$ALERT2ATTACK_STUDIO_ROOT/exp004-n14` (QLoRA) or `…/exp005-graph-only` (graph-only) | logs, GGUF, eval export |

`EXP004_ROOT` remains an alias for `ALERT2ATTACK_EXP_DIR` on `lightning_qlora_run.sh`.
Model tags (`casefile-qlora-n14`, `qwen2.5:7b-instruct`) and eval flags are unchanged.

Print resolved paths without starting Ollama/train/eval:

```bash
ALERT2ATTACK_PRINT_PATHS=1 ./scripts/lightning_qlora_run.sh
ALERT2ATTACK_STUDIO_ROOT=/tmp/studio ALERT2ATTACK_EVAL_DIR=/tmp/eval ALERT2ATTACK_EXP_DIR=/tmp/exp \
  ALERT2ATTACK_PRINT_PATHS=1 ./scripts/lightning_qlora_smoke.sh
```

Weights, adapters, GGUF, and HF caches stay gitignored. `reports/` is ignored as before.
Recipe / gates: `docs/plans/2026-09-09-finetune-lora-followup.md` (DR-011/012 unchanged).
