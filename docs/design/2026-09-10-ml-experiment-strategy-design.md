# ML experiment strategy: alert2attack

**Design spec, 2026-09-10.** Status: ML Lead baseline. Not a training approval.  
Companion tracker: `docs/experiments/TRACKER.md`.  
Decision: `docs/experiments/DR-2026-09-10-001-reject-lora-until-live-eval.md`.  
Discuss gate: `docs/experiments/DR-2026-09-11-011-lora-discuss-gate.md` (DR-011).  
Live-eval campaign (next work): `docs/superpowers/plans/2026-09-10-live-eval-campaign.md`.  
Gated LoRA recipe: `docs/superpowers/plans/2026-09-09-finetune-lora-followup.md` (**not approved**).

## 0. Status + recommendation

**Status.** v1 (phases 1–6) is in the repo. The README **results** table is still empty (full held-out test N=13 has not been run). An official N=3 teacher vs B0 *slice* is recorded under DR-011; that is not a headline row. Distill JSONL is still not training-ready.

**Recommendation.** Do not train. Do not treat the N=3 slice as EXP-001. LoRA stays unlaunched until ML Lead “Approved for launch” + Deimos cost OK. Distill/QLoRA drafting is allowed; GPU is not. Discuss gate: DR-011.

## 1. Why this document exists

Own the experiment strategy for this repo: what to measure, what “better” means, which runs are worth money, and when to stop. Fine-tuning is a follow-up, not the product. The product is a sourced investigation loop with a local 7B default (`docs/superpowers/specs/2026-09-09-edr-investigation-agent-design.md` §9).

Hard stops (ML Lead):

- Never launch a training job from this role.
- Never push to `main` or merge PRs.
- Never spend API / GPU money without explicit human approval.
- Never change the evaluation protocol without a written change note and confirmation.

## 2. Approaches considered

**A. Measure the loop first (chosen).** Live `b0` vs `agent-local-7b` vs `agent-teacher` on **test**, N=13, frozen metrics. Then, only if the DR-011 discuss gate clears on official held-out eval, collect **dev** teacher traces and consider LoRA (still requires “Approved for launch”).

Why: the design already states investigation quality is dominated by tools, verifier, and eval — not weights. We have no numbers. Training now cannot be interpreted.

**B. Jump to LoRA / QLoRA now (rejected).** The existing follow-up plan is not launchable: `--export-distill` does not persist teacher chat transcripts (`scripted_prompt_messages` only fires for `ScriptedChat`), `LlmCallRecord` stores character counts not messages, and `alert2attack eval run` has no `--model` flag for a LoRA tag. Dataset after filters would be ≤20 investigations. Cargo-cult.

**C. Prompt / graph ablations before any live eval (rejected as first move).** `agent-noplan` and budget sweeps were YAGNI in v1. They become useful **after** we know whether the 7B fails at tool calling, writing, or citation — which requires EXP-001 numbers plus traces.

## 3. Frozen evaluation protocol (do not change)

This is the protocol **as implemented today**. Changing any item below requires a protocol-change note and human confirmation.

### 3.1 Splits and dataset

| Split | N | malicious | likely_benign | not_enough_evidence |
|---|---:|---:|---:|---:|
| `dev` | 20 | 14 | 3 | 3 |
| `test` | 13 | 8 | 3 | 2 |

- Origin: all 33 committed scenarios are `otrf` (no hand-authored event rows).
- Test is held out. Prompt, graph, and LoRA work use **dev only**.
- Reports record `dataset_hash` = SHA256 of all `manifest.yaml` bytes, truncated to 16 hex chars (`src/alert2attack/eval/runner.py`).

### 3.2 Headline arms (README table)

| Arm | What it is | LLM |
|---|---|---|
| `b0` | Single prompt, ≤40 events inlined, no tools | Ollama `qwen2.5:7b-instruct` (or `ALERT2ATTACK_OLLAMA_MODEL`) |
| `agent-local-7b` | Full graph + verifier/repair ≤2 | same Ollama default |
| `agent-teacher` | Full graph + verifier/repair ≤2 | ExpLabs `gpt-5.6-luna` if `EXPLABS_API_KEY`, else OpenAI `gpt-4o-mini` |

CI-only: `agent-scripted`. Diagnostic, not in README: `agent-noverify`.

Temperature is **0.0** in `OpenAICompatibleChat`. Prefer that. Do not introduce sampling for headline numbers.

### 3.3 Headline metrics (README columns)

Defined in `src/alert2attack/eval/metrics.py` and rendered by `scripts/render_eval_table.py`:

| Column | Field | Definition |
|---|---|---|
| Verdict acc | `verdict_accuracy` | Exact match `pred.verdict == gold.verdict` (4-class pred vs 3-class gold; `suspicious` is a miss costing 1) |
| Mean cost | `mean_verdict_cost` | Severity matrix: mal→benign=5, mal→NEE=3, mal→suspicious=1, benign→mal=2, other miss=1, match=0 |
| Citation post | `mean_citation_validity_post` | Fraction of claim evidence ids that are in this-run ledger (post repair) |
| Key-pid recall | `mean_key_pid_recall` | `\|gold.key_pids ∩ involved_pids\| / \|gold.key_pids\|`; **empty gold key_pids scores 1.0** |
| Action safety | `action_safety_rate` | 1 if predicted actions ∩ `gold.unacceptable_actions` is empty |

Also computed but **not** in the README table (still frozen, still reported in JSON): technique F1, persistence recall, citation pre, unsupported-claim rate, acceptable-action rate, tool/LLM call means, budget-exhaustion rate.

Citation **pre-repair** uses a heuristic (`max(0, 1 - 0.15 * n_citation_errors)`) when `pre_repair_errors` is non-empty. That is frozen. Do not “fix” it mid-campaign.

### 3.4 LoRA / distill discuss gate (DR-011, operational)

Copied from README / `docs/RUN.md`. Deimos confirmed; ML Lead locked. **No metric-code change.**

On the official held-out eval, **teacher vs B0**:

1. Teacher **≥** B0 on `citation_post` (`mean_citation_validity_post`) **AND** `key_pid_recall` (`mean_key_pid_recall`).
2. Teacher **strictly beats** B0 on **at least one** of:
   - `action_safety` (`action_safety_rate`) higher
   - `mean_cost` (`mean_verdict_cost`) lower
   - `verdict_acc` (`verdict_accuracy`) higher

Ties on citation+key_pid alone are **not** enough. Larger N hoping B0 dips is **not** the plan.

Headline rows remain full N (no `--limit`). An N=3 official test-id slice may be recorded as a slice, not as the README headline. Report N and per-case outcomes. Do not paste scripted smoke numbers.

Discuss ≠ launch. LoRA stays unlaunched until ML Lead “Approved for launch” + Deimos cost OK. Distill/QLoRA drafting is allowed; GPU is not.

### 3.5 Proposed protocol clarifications (not in force)

These are **not** approved. Do not implement until a human confirms a protocol-change note.

1. **Matched-model B0.** Today `b0` is 7B-no-tools vs teacher-with-tools (confounded). A diagnostic `b0-teacher` arm would isolate “loop vs single-shot” at constant model. Headline table stays 7B-B0 until confirmed.
2. **Empty `key_pids`.** Two golds score 1.0 by vacuity (`otrf_covenant_installutil` on **dev**, `otrf_empire_schtasks_creation_execution_elevated_user` on **test**). Exclude from the mean or fill gold — after confirmation.
3. **Duplicate key_pids.** Many golds list the same pid twice; set intersection hides it. Dedup in gold, not in the metric.
4. **Prompt hash / model tag / seed** in the report JSON (design §7.2 asked for this; only `dataset_hash` + `trace.model` exist).
5. Persist full teacher transcripts in distill (required before any SFT; this is **plumbing**, not a metric change).

## 4. Architecture (training path, gated)

```
teacher eval (dev) ──▶ distill JSONL ──▶ filter ──▶ QLoRA SFT (7B) ──▶ Ollama tag ──▶ eval (test)
        │                                      │
        └── gate: DR-011 discuss on test ───────┘  must already be true; launch is separate
```

Units:

| Unit | Role | Rule |
|---|---|---|
| `alert2attack.eval.runner` | Arm execution + report JSON | Test split is read-only for measurement |
| `alert2attack.eval.distill` | JSONL for SFT | Must contain OpenAI-style messages; today it does **not** for teacher |
| `alert2attack.eval.metrics` | Frozen scorer | No silent edits |
| Student weights | `qwen2.5:7b-instruct` QLoRA | Default product path; 8 GB VRAM |
| Teacher | ExpLabs / OpenAI | Ablation and distill source only |

The student stays Qwen2.5-7B-Instruct. We do not switch base models to chase a leaderboard while the loop is unmeasured.

## 5. Hyperparameter philosophy

1. **One lever per run.** After the gate: first LoRA is a single config (rank 8, 1 epoch). No grid.
2. **Capacity matches data.** Filtered teacher investigations ≤ 20. Rank 8, α=16, 1 epoch. Rank 16 or epoch 2 only if train loss is still high and **dev** citation does not drop.
3. **Train the skill that is missing.** SFT targets are tool-calling turns **and** the write turn from filtered runs, not verdict labels. Verdicts are scored, not trained as classification.
4. **No packing** of unrelated conversations (breaks Qwen tool-call templates).
5. **QLoRA 4-bit** on the 8 GB box. Full fine-tune is out.
6. **Kill early.** If filtered N < 12, do not train — collect more teacher traces or stop. If action safety falls on a 3-case smoke, stop the run.

Exact first-LoRA config (documented for later; **not approved for launch**):

| Knob | Value |
|---|---|
| Base | `unsloth/Qwen2.5-7B-Instruct` (or HF `Qwen/Qwen2.5-7B-Instruct` + bitsandbytes) |
| Quant | 4-bit NF4, QLoRA |
| Rank / α / dropout | 8 / 16 / 0 |
| Targets | `q_proj,k_proj,v_proj,o_proj,gate_proj,up_proj,down_proj` |
| LR / schedule / warmup | 2e-4 / cosine / 0.03 |
| Epochs | 1 |
| Batch / accum | 1 / 8 (effective 8) |
| Max seq | 4096 (drop to 2048 if OOM; do not raise to 8192 on 8 GB without a smoke) |
| Optim | adamw_8bit |
| Template | Qwen2.5 instruct + tool calls |
| Split | train = filtered **dev** traces; eval during train = 2 held-out **dev** cases, never test |

## 6. Success and kill criteria

### 6.1 EXP-001 live eval (next)

Success: three JSON reports on test, full N=13, pasted into README, with model tags and `dataset_hash`.

Kill / stop a live arm: repeated parse failures, budget-exhaustion rate > 0.5, or API errors. Truncated `--limit` runs are plumbing, not headline.

### 6.2 Loop proof (LoRA/distill discuss, DR-011)

Teacher vs B0 satisfies §3.4 (≥ citation_post and key_pid_recall, plus a strict beat on action_safety / mean_cost / verdict_acc). If the gate fails, debug tools/prompts/verifier on **dev**, do not train. Passing discuss does **not** authorize GPU.

### 6.3 LoRA (only after unlock + distill fix)

Must all hold on **test** vs the untuned `agent-local-7b` report with the same `dataset_hash`:

- citation post **up**
- key-pid recall **up**
- action safety **not down**

Kill the run if: train loss diverges; smoke-3 action safety drops; student starts emitting ids outside the ledger more than baseline; or wall time > 4 h on the 8 GB box without a first checkpoint.

## 7. Cost and time (estimates, not approvals)

Estimates assume sequential eval, default budgets (`max_tool_calls=12`, `max_llm_calls=20`, `timeout_s=180`).

| Work | Compute | Time (order) | Money |
|---|---|---|---|
| `b0` test N=13 | local 7B, 1 call/case | 10–30 min | $0 |
| `agent-local-7b` test N=13 | local 7B, up to 20 LLM calls/case | 45–180 min | $0 |
| `agent-teacher` test N=13 | ExpLabs / OpenAI | 30–120 min | **API spend — human must approve** |
| Teacher **dev** distill N=20 | same | 1–3 h | **API spend — human must approve** |
| First QLoRA (when approved) | RTX 4060 8 GB | 1–3 h | local power, or cloud GPU if human chooses |

No dollar cap is authorized in this spec. Teacher eval is the only likely cash cost before LoRA. Do not start it without a human “yes” on the key and the spend.

## 8. Queue (highest leverage first)

1. **EXP-001** — live test eval, three headline arms. Unblocks every later decision.
2. **EXP-001b** (optional, needs protocol confirmation) — `b0-teacher` diagnostic.
3. **PLUMB-DISTILL** — persist teacher messages in JSONL. Required before SFT; does not change metrics.
4. **EXP-002** — error analysis on traces (7B tool-call fail vs write fail vs citation fail). Decides whether LoRA, prompts, or tools are the lever.
5. **EXP-003** — teacher **dev** distill after gate.
6. **EXP-004** — single QLoRA run. Only with an “Approved for launch” note naming config, data hash, and cost.

Killed until EXP-001 exists: 14B offload ablation, rank/LR sweeps, DPO/ORPO, multi-base bake-offs, synthetic extra scenarios for training.

## 9. How other bots get a launch approval

Submit a plan with: hypothesis, arm, split, exact command, model tag, estimated time/cost, success metric, kill switch. ML Lead replies with one of:

- **Approved for launch** — exact config + expected cost/time.
- **Rejected** — reason and what evidence is missing.
- **Revise** — protocol or confound to fix.

No approval in this document covers training or paid teacher traffic.
