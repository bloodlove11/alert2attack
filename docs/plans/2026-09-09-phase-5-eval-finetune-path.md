# Phase 5: Eval Harness + Fine-tune Path

> Goal: Deterministic scoring of investigation arms; persist traces so LoRA distillation is a measured follow-up (not v1 training).

Architecture: `alert2attack.eval` scores `(CaseFile, Trace, VerificationReport)` against `Gold`. Arms: `b0`, `agent-scripted` (CI), `agent-local-7b`, `agent-teacher`, `agent-noverify`. Reports under `reports/`. Distillation export writes OpenAI-style message JSONL from teacher/scripted runs.

Fine-tune (post-eval): See `docs/plans/2026-09-09-finetune-lora-followup.md`: only after this harness is green and DR-011 discuss is cleared (then still needs "Approved for launch").

### Deliverables
1. Metrics (verdict cost, technique F1, scope, citation pre/post, action safety, efficiency)
2. B0 single-prompt baseline
3. `alert2attack eval run --arm … --split …`
4. Trace to distillation JSONL exporter
5. Fine-tune follow-up plan (LoRA recipe, gates, out of v1 merge)
