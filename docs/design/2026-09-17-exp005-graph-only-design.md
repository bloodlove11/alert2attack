# EXP-005 graph-only N=13 control — design

**Status:** Measured. Official N=13 0.54 / 1.85 / 1.00 / 0.85 / 1.00. Acc/safety vs EXP-001 are the graph; QLoRA is cost + extra key-pid.  
**Date:** 2026-09-17  
**Related:** DR-016, EXP-004, EXP-001, lever-6 3-case **dev** smoke action_safety 1.00

## Problem

EXP-004 mixes rank-8 QLoRA and graph levers 1–6. Cannot read 0.00→0.54 vs EXP-001 as a weights result.

## Approaches

1. **Official N=13 of untuned 7B on the lever-6 tree (chosen).** Same host, digest, split, timeout as EXP-001/004. No train.
2. **Retrain QLoRA without levers (rejected).** Costs another SFT; does not answer “what did the graph do on the EXP-001 baseline.”
3. **14B / sweep (rejected).** KILL-14B, KILL-SWEEP.

## Design

- Ollama `qwen2.5:7b-instruct` digest `845dbda0ea48`.
- Eval tree includes lever 6 (`alert2attack-lever6` / this branch).
- `ALERT2ATTACK_OLLAMA_MODEL` unset or that tag. Never `casefile-qlora-n14`.
- `--arm agent-local-7b --split test --out reports/exp005-graph-only`.
- Recast `num_ctx` 8192 only if write overflows 4096 (same as EXP-004 smoke).
- Record TRACKER EXP-005 + README control row. Stop Studio.

## Out of scope

- New graph lever
- DR-012 change
- `metrics.py` change
- Headline overwrite of EXP-001 / EXP-004
