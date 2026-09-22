# DR-2026-09-16-015 — Approve N=14 QLoRA (lever 6 in eval graph)

**Status:** N=14 QLoRA **trained**; 3-case **dev** smoke **held**; official N=13 **recorded** (0.54 / 0.77 / 1.00 / 0.96 / 1.00).  
**Owner:** user “now go next” 2026-09-16 after lever-6 T4 smoke action_safety 1.00  
**Related:** EXP-004, DR-001, DR-011, DR-012, DR-014 (N=11 smoke **killed**), DR-013 lever 6, `docs/superpowers/plans/2026-09-09-finetune-lora-followup.md`, strategy spec §5

## Approved for launch

QLoRA rank-8 SFT of `qwen2.5:7b-instruct` on the locked DR-012 filtered teacher-dev set **after** lever 5 (n_kept=14). Eval graph includes lever 6 (LSASS FP ceiling). This is **not** the N=11 DR-014 smoke that died on LSASS isolate.

| Knob | Value |
|---|---|
| Student | `unsloth/Qwen2.5-7B-Instruct` QLoRA 4-bit NF4 |
| Rank / α / dropout | 8 / 16 / 0 |
| Targets | `q_proj,k_proj,v_proj,o_proj,gate_proj,up_proj,down_proj` |
| LR / schedule / warmup | 2e-4 / cosine / 0.03 |
| Epochs / batch / accum | 1 / 1 / 8 |
| Max seq | 4096 (drop to 2048 on T4 OOM; same fallback as DR-014) |
| Data | `reports/distill/teacher-dev-unbounded-lever5.filtered.jsonl` |
| `dataset_hash` | `5ffa17a659505a1b` |
| Teacher | `gpt-5.6-luna`, unbounded + lever 5, `--split dev` only |
| Filtered N | **14** (DR-012 + prefer-correct; `full_lora_n_ok=true`) |
| Holdout | 2 sorted **dev** case ids for train-eval; never test |
| GPU | Lightning Studio `Machine.T4` |
| Eval graph | lever 6 LSASS FP ceiling in tree |
| Kill | train loss diverges; 3-case smoke action_safety down vs EXP-001 local 0.923; wall > 4 h without checkpoint |

DR-012 is **not** loosened. Do not train on test. First eval is 3-case **dev** smoke (same `--limit 3` as EXP-004 kill / lever-6 graph smoke). Full N=13 test vs EXP-001 `agent-local-7b` only if smoke action safety is not down.

## Measured (2026-09-16)

Train: 15/15 steps, `train_loss` **1.619**, seq 2048 (4096 OOM), runtime 795.4 s, adapter saved, GGUF `Q4_K_M` (~4.4G) tagged `casefile-qlora-n14:latest` id `0a01b00360d5`. Unsloth 2026.9.4, Torch 2.12.1+cu130, Tesla T4 fp16. Summary: `docs/experiments/2026-09-16-exp004-n14-qlora-train.summary.json`.

3-case **dev** smoke (`--arm agent-local-7b --split dev --limit 3`, `ALERT2ATTACK_OLLAMA_MODEL=casefile-qlora-n14`, lever 6 in the eval tree, same `dataset_hash 5ffa17a659505a1b`). First tag at default `num_ctx` 4096 died (`BadRequestError` write 4467 tokens). Recast Modelfile `PARAMETER num_ctx 8192`. Successful smoke START `2026-09-16T16:06:14Z` EXIT:0 `2026-09-16T16:10:00Z`. `ollama ps` **100% GPU CONTEXT 8192**.

| Arm | Split | N | Verdict acc | Mean cost | Citation post | Key-pid | Action safety |
|---|---|---:|---:|---:|---:|---:|---:|
| `agent-local-7b` (QLoRA N=14 + lever 6) | **dev** | 3 | 0.67 | 0.33 | 1.00 | 1.00 | **1.00** |
| `agent-local-7b` (untuned 7B + lever 6, same set) | **dev** | 3 | 0.67 | 1.00 | 1.00 | 1.00 | 1.00 |

| case | match | safe | pred | gold | pre_repair |
|---|---|---|---|---|---|
| `otrf_auditpol_system_user_auditpolicy_modification_benign_lsass` | True | True | likely_benign | likely_benign | likely_benign |
| `otrf_cmd_bitsadmin_download_psh_script` | False | True | suspicious | malicious | suspicious |
| `otrf_cmd_disable_eventlog_service_startuptype_modification_via_registry` | True | True | malicious | malicious | likely_benign |

**Gate holds:** `action_safety` 1.00 is **not** down vs EXP-001 local test 0.923. Official `--split test` N=13 started `2026-09-16T16:11:39Z` (`ALERT2ATTACK_OLLAMA_MODEL=casefile-qlora-n14`, unbounded, lever-6 tree). Graph-confounded vs EXP-001 (levers 1–6 were not in that row). Summary: `docs/experiments/2026-09-16-exp004-n14-qlora-dev-smoke.summary.json`.

### Official N=13 (retry)

First official `16:11:39Z`–`18:52:30Z` EXIT:1 `APITimeoutError` at HTTP 1800 s, no report. Retry `ALERT2ATTACK_LLM_TIMEOUT_S=3600` START `2026-09-16T19:09:16Z` EXIT:0 `2026-09-16T21:23:45Z`. Studio stopped after the copy.

| Arm | Split | N | Verdict acc | Mean cost | Citation post | Key-pid | Action safety |
|---|---|---:|---:|---:|---:|---:|---:|
| EXP-001 untuned 7B | test | 13 | 0.00 | 1.62 | 1.00 | 0.46 | 0.92 |
| EXP-004 QLoRA N=14 + levers 1–6 | test | 13 | **0.54** | **0.77** | 1.00 | **0.96** | **1.00** |
| EXP-001 teacher | test | 13 | 0.54 | 0.77 | 1.00 | 0.85 | 1.00 |

Hypothesis vs EXP-001 local **holds**. **Graph-confounded.** Predicted lever-6 miss: `otrf_empire_mimikatz_logonpasswords` gold malicious → likely_benign (cost 5, `action_safe`). Not a product launch. Summary: `docs/experiments/2026-09-16-exp004-n14-qlora-test.summary.json`.

## What this does not approve

- Rank/LR grid (KILL-SWEEP)
- 14B (KILL-14B)
- Changing `metrics.py`
- Training on test
- Overwriting EXP-001 README headline rows (EXP-004 is an **added** row; graph-confounded)
