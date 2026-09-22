# Fine-tune follow-up (LoRA): after Phase 5

> ML Lead status (2026-09-11): NOT APPROVED FOR LAUNCH.  
> Launch rejection: `docs/experiments/DR-2026-09-10-001-reject-lora-until-live-eval.md`.  
> Discuss gate: `docs/experiments/DR-2026-09-11-011-lora-discuss-gate.md` (DR-011 locked).  
> Strategy: `docs/design/2026-09-10-ml-experiment-strategy-design.md`.  
> This file remains the gated recipe. It is not part of v1 delivery (design §9). Distill/QLoRA drafting is allowed; GPU is not.

Gate (must all be true before launch):

1. Live README Results exist for `b0` and `agent-teacher` on test, full N, same `dataset_hash` (N=3 slices are not this row).
2. DR-011 discuss: teacher ≥ B0 on citation post and key-pid recall, and teacher strictly beats B0 on at least one of action safety (higher) / mean cost (lower) / verdict acc (higher). Ties on citation+key_pid alone are not enough.
3. Distill JSONL contains real teacher transcripts (PLUMB-DISTILL). Today it does not.
4. Filtered dev N ≥ 12.
5. Human approval of API spend (distill) and GPU/time (train): Deimos cost OK.
6. A new decision record with an explicit Approved for launch block.

Until then: do not train, do not pull Unsloth "just to try."

## Why not now

Investigation quality is dominated by tools, verifier, and eval: not weights. Fine-tuning without a held-out metric and teacher traces is cargo-cult. As of 2026-09-11 the README results table is still empty; the DR-011 N=3 slice is not a launch baseline.

Code gaps vs this recipe:

- `--export-distill` only fills `messages` for `ScriptedChat` (`src/alert2attack/eval/distill.py`). Teacher/Ollama leaves `messages: []`. `LlmCallRecord` stores character counts, not turns.
- `alert2attack eval run` has no `--model` flag. Re-eval of a LoRA tag must use `ALERT2ATTACK_OLLAMA_MODEL` (or a CLI flag that does not exist yet). Do not pretend `--model <lora-tag>` works.

## Recipe (when gated and approved)

1. Generate teacher traces (dev split only): separate spend approval.

   ```bash
   uv run alert2attack eval run --arm agent-teacher --split dev --export-distill reports/distill/teacher-dev.jsonl --out reports
   ```

   Each line must contain OpenAI-style messages (system/user/assistant/tool) + final CaseFile + `scenario_id` + `verification_status`. If `messages` is empty, stop: PLUMB-DISTILL is not done.

2. Filter  
   Keep runs with `verification.status in {passed, repaired}` and `citation_validity_post ≥ 0.9`. Drop degraded / budget-exhausted. Drop any `split != "dev"`. If surviving N < 12, do not train.

3. LoRA SFT of `qwen2.5:7b-instruct` (8 GB VRAM: QLoRA 4-bit). First approved config only (strategy spec §5): rank 8, α 16, dropout 0, LR 2e-4, 1 epoch, batch 1, grad accum 8, max seq 4096, Unsloth or bitsandbytes, Qwen2.5 tool-calling template. Train tool-call and write turns. Do not train on test. Do not grid-search.

4. Re-eval (after a load path exists):

   ```bash
   ALERT2ATTACK_OLLAMA_MODEL=<ollama-lora-tag> uv run alert2attack eval run --arm agent-local-7b --split test --out reports
   ```

   Compare to the EXP-001 untuned local row, same `dataset_hash`. Report delta vs untuned local and vs teacher.

5. Success bar  
   LoRA must improve citation post and key-pid recall vs untuned local without worsening action safety.

## Rationale

Architecture is distillation-ready in intent (traces + verifier + eval). We measure the untuned local baseline first; LoRA is an optional lift after the loop is proven and after transcripts actually land on disk.
