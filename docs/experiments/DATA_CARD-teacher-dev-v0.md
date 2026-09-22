# DATA_CARD-teacher-dev-v0

**Status: DRAFT / NOT READY for launch** — DR-012 filter is **locked**. Latest live artifact is the **unbounded + lever 5** 2026-09-16 export: `n_kept=14` (`full_lora_n_ok=true`; gitignored JSONL; committed summary: `docs/experiments/2026-09-16-teacher-dev-unbounded-lever5.filtered.summary.json`). Smoke SFT discuss **clears**; full LoRA N≥12 **clears**. That is **not** “Approved for launch.”  
**Purpose:** QLoRA SFT **draft**. This card does **not** authorize GPU.  
**Do not launch LoRA** until an explicit “Approved for launch” record. DR-011 discuss is cleared on an N=3 slice.

Named filter revision: **DR-012** (`docs/experiments/DR-2026-09-11-012-distill-filter.md`).  
Related: `docs/experiments/TRACKER.md` (EXP-003, DR-012), `docs/experiments/DR-2026-09-10-001-reject-lora-until-live-eval.md`, `docs/experiments/DR-2026-09-11-011-lora-discuss-gate.md`, `src/alert2attack/eval/distill.py`.

## Source

Official distill command (README / EXP-003):

```bash
uv run alert2attack eval run --arm agent-teacher --split dev --export-distill reports/distill/teacher-dev.jsonl
```

| Field | Value |
|---|---|
| Arm | `agent-teacher` only |
| Split | **`dev` only** |
| Export path | caller-supplied (default `reports/distill/teacher-dev.jsonl`) |
| `reports/` | gitignored / not in the repo — the filter **must** take an input path |

Never export or invent **test**-split rows. Never push large binaries to `main` without review.

Teacher message plumbing landed (PLUMB-DISTILL code). **2026-09-16 lever 5:** live `gpt-5.6-luna` teacher-dev export kept **14** under DR-012 (`full_lora_n_ok=true`). That still does **not** make this card a launch approval.

## Filter rules (DR-012)

Applied by `scripts/filter_teacher_dev_distill.py` in this order (first match is the drop reason):

1. Drop if `split` is present and `split != "dev"`. Never test.
2. Drop unknown / failed verification: keep only `verification_status in {passed, repaired, degraded}`. On a distill row this is top-level **`verification_status`** (`distill_record`); nested `verification.status` is also accepted.
3. Keep only **citation_post ≥ 0.9** (row field or recompute; see below). Missing score with no `case_file` → `citation_unavailable`.
4. **`passed` / `repaired`:** keep even if tool/budget exhausted (`trace.budget.tool_exhausted` / `llm_exhausted`, or top-level flags). Exhaustion is **not** a hard drop.
5. **`degraded`:** keep **only if** citation ≥ 0.9 **and** verdict_match (`case_file.verdict` equals `gold_verdict`). Else drop `degraded_no_verdict_match`. This rule holds even with `--no-prefer-correct-verdict`.
6. `--prefer-correct-verdict` (**default on**): drop verdict mismatches for **all** statuses when both `case_file.verdict` and `gold_verdict` are present (`verdict_mismatch`). Disable with `--no-prefer-correct-verdict`. Degraded mismatches still use `degraded_no_verdict_match`, not this reason.

Do **not** silently loosen beyond this list.

Summary JSON reports `dropped_by_reason` (including `degraded_no_verdict_match`) and `degraded_kept`. `tool_exhausted` is not a drop reason under DR-012.

### Kill lines (smoke vs full LoRA)

| Gate | Filtered N | Meaning |
|---|---:|---|
| Smoke SFT **discuss** | **≥ 8** | Clears first-draft smoke SFT *discuss* only. Summary: `smoke_sft_discuss_clears` / `kill_filtered_n_lt_8`. |
| Full LoRA | **≥ 12** | Still required for a full LoRA attempt, via a **later named re-export** (higher repair/tool budget). Summary: `full_lora_n_ok` / `kill_filtered_n_lt_12`. |

**N<12 is not training-ready for full LoRA.** Latest measured export is **n_kept=14** (2026-09-16 lever 5). The filter does not invent extra rows to pad N. `ready=true` only means “kept ≥1 row and at least one kept row has non-empty `messages`.” It is **not** “Approved for launch.”

### citation_post field path

**`distill_record` does not store `citation_post` / `citation_validity_post`.**  
Eval computes `CaseScore.citation_validity_post` in `src/alert2attack/eval/metrics.py` as `citation_validity(case_file, ledger_ids)` and writes it to **eval reports** (`report.cases[].citation_validity_post`), not to the JSONL.

`eval.runner` builds the ledger as `{eid for c in result.trace.tool_calls for eid in c.evidence_ids}`.

The filter therefore:

1. Uses `row.citation_validity_post` or `row.citation_post` (or the same keys under `row.scores`) when present.
2. Otherwise **recomputes** that frozen formula from `case_file` claims vs `trace.tool_calls[].evidence_ids`.

Empty claim-evidence slots score **1.0** (same as `citation_validity`). Missing `case_file` with no explicit score → drop `citation_unavailable`.

## Expected columns / schema (`distill_record`)

Each JSONL line is one dict from `distill_record`:

| Key | Source | Notes |
|---|---|---|
| `scenario_id` | `scenario.scenario_id` | Catalog id |
| `split` | `scenario.split` | Must be `dev` after filter |
| `model` | `result.trace.model` | Teacher model tag |
| `verification_status` | `result.verification.status` | `passed` / `repaired` / `degraded` / … |
| `case_file` | `result.case_file.model_dump(mode="json")` | Full CaseFile including `verdict` |
| `trace` | llm_calls, tool_calls, budget, notes | `LlmCallRecord` may include messages after PLUMB-DISTILL; char counts remain |
| `messages` | recorded teacher turns (`turns_from_trace`) | OpenAI-style threads; must be non-empty for `ready` |
| `gold_verdict` | `scenario.gold.verdict` | Gold class for verdict_match / prefer-correct-verdict |

## Evidence (N=20 teacher-dev exports)

Live `ALERT2ATTACK_TEACHER_MODEL=gpt-5.6-luna`, `dataset_hash 5ffa17a659505a1b`. JSONL is gitignored.

| Quantity | Capped 2026-09-15 | Unbounded 2026-09-15 | Lever 4 2026-09-16 | Lever 5 2026-09-16 |
|---|---|---|---|---|
| Committed summary | `docs/experiments/2026-09-15-teacher-dev-filtered.summary.json` | `docs/experiments/2026-09-15-teacher-dev-unbounded.filtered.summary.json` | `docs/experiments/2026-09-16-teacher-dev-unbounded-lever4.filtered.summary.json` | `docs/experiments/2026-09-16-teacher-dev-unbounded-lever5.filtered.summary.json` |
| citation_post | 1.00 | 1.00 | 1.00 | 1.00 |
| verdict_acc | 0.50 | 0.55 | 0.55 | **0.70** |
| mean_cost | 1.30 | 1.05 | 1.05 | **1.00** |
| key-pid recall | — | 0.85 | 1.00 | 1.00 |
| action_safety | — | 1.00 | 1.00 | **0.95** |
| budget_exh | 0.85 | 0.00 | 0.00 | 0.00 |
| mean tools | 11.85 | 14.15 | 14.3 | **14.4** |
| DR-012 n_kept | 10 | 11 | 11 | **14** |

Smoke SFT discuss **clears** (N≥8). Full LoRA N≥12 **clears** (14≥12). Lever 5 kept all three NEE twins via the thin-window ceiling (dev acc +0.15 = 3/20). Leftover 6 drops are gold-malicious write misses. **Not** a launch. Do not loosen DR-012. Dev-only; not a README headline row.

## Quality gates

| Gate | Rule |
|---|---|
| Empty `messages` | **FAIL ready.** If every kept row has empty `messages`, the filter sets `ready=false` and exits non-zero. |
| Schema | Keep distill keys listed above; filter does not rewrite `case_file` / `trace`. Invalid JSON lines are dropped (`invalid_row`). |
| Token-length stats | **TBD after a DR-012 filtered artifact** (no `reports/` artifact in git). |
| Sample inspection | **Required** before any SFT: open kept rows, confirm tool-call transcripts exist, verdicts, and citations. |
| Filtered N | Catalog **N_dev = 20**. Unbounded + lever 5 2026-09-16: **n_kept=14** (measured). |
| Split | Never test. Never synthesize test-split rows. |

This card stays **NOT READY** for launch. The 2026-09-16 lever-5 filtered artifact is inspectable locally and summarized in git; `full_lora_n_ok=true` is **not** launch approval.

## Sizes

| Quantity | Value |
|---|---|
| Catalog N_dev | **20** |
| Catalog N_test | 13 (held out; do not distill) |
| Filtered N (2026-09-16 unbounded+lever5, DR-012+prefer-correct) | **14** (gitignored JSONL; committed summary) |
| Smoke SFT discuss | filtered N ≥ **8** |
| Full LoRA N gate | filtered N ≥ **12** — **clears** at n_kept=14 |
| Full LoRA launch | still needs an explicit “Approved for launch” record; not this card |

## How to run the draft filter

`reports/` is gitignored. Point the CLI at a local export:

```bash
uv run python scripts/filter_teacher_dev_distill.py \
  reports/distill/teacher-dev.jsonl \
  --out reports/distill/teacher-dev.filtered.jsonl \
  --summary reports/distill/teacher-dev.filtered.summary.json
```

No network. No training. `--prefer-correct-verdict` is on by default (DR-012).

## Status

**DRAFT / NOT READY for launch.** DR-012 is locked. n_kept=14 clears the full-LoRA N≥12 gate and does **not** authorize GPU. Do not treat this card, the fixture JSONL under `tests/fixtures/distill/`, or `ready=true` as launch approval.
