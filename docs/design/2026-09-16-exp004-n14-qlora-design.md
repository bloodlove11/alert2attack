# EXP-004 N=14 QLoRA: design

Status: Spec. One rank-8 QLoRA on n_kept=14. Lever 6 in the eval graph.  
Date: 2026-09-16  
Related: DR-015, DR-014 (N=11 kill), DR-012, lever 6 T4 smoke action_safety 1.00

## Problem

Full LoRA N≥12 clears (n_kept=14). Lever 6 3-case dev T4 smoke of the untuned 7B is action_safety 1.00 on the set that killed EXP-004 QLoRA at 0.67. The remaining EXP-004 question is whether rank-8 QLoRA on the lever-5 teacher-dev keep-set lifts citation/key-pid vs untuned 7B without hurting action safety.

## Approaches

1. One QLoRA on n_kept=14, eval graph includes lever 6 (chosen). Spec §5 knobs. T4. Seq 2048 if 4096 OOMs. 3-case dev smoke first.
2. Retrain the N=11 adapter (rejected). That run died on LSASS FP; N<12; traces lack the three NEE-twin keeps.
3. 14B / rank sweep (rejected). KILL-14B, KILL-SWEEP.
4. Official test first (rejected). Smoke gate stands.

## Design

- Prepare SFT threads from `teacher-dev-unbounded-lever5.filtered.jsonl` without `--allow-smoke`.
- Hold out the last two sorted dev case ids. Never test.
- Train `unsloth/Qwen2.5-7B-Instruct` QLoRA 4-bit NF4 rank 8 / α 16 on Lightning T4, fp16.
- Export GGUF `Q4_K_M`, Ollama tag `casefile-qlora-n14`.
- 3-case dev smoke: `ALERT2ATTACK_OLLAMA_MODEL=casefile-qlora-n14` `--arm agent-local-7b --split dev --limit 3` on the lever-6 tree.
- Kill official test if `action_safety` < EXP-001 local 0.923.
- No `metrics.py`. No DR-012 change.

## Out of scope

- Teacher-dev re-export with lever 6 (n_kept already 14; ceiling is graph-side)
- Headline overwrite without a later official test row
