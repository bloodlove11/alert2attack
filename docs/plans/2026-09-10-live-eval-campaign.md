# Live eval campaign (EXP-001)

> **For agentic workers:** This is a **measurement** campaign, not a training job. Do not start LoRA. Do not push to `main`. Do not spend teacher API money until a human has approved the key and the spend. REQUIRED: follow this plan in order; paste live numbers into README only after full-N test runs.

**Goal:** Fill the README Results table with live `b0`, `agent-local-7b`, and `agent-teacher` scores on the frozen **test** split (N=13).

**Status `2026-09-12`:** Tasks 1–6 done. All three headline arms are in README Results at N=13,
`dataset_hash 5ffa17a659505a1b`. `agent-local-7b` ran on Lightning Studio Tesla T4
(same Ollama tag/digest as the CPU diagnostic). No LoRA, no training.

**Architecture:** Use the existing eval harness (`src/alert2attack/eval/runner.py`). One arm per command. Write `reports/<date>-<arm>-test.json`. Merge with `scripts/render_eval_table.py`. Do not change `src/alert2attack/eval/metrics.py`.

**Tech Stack:** `uv`, Ollama `qwen2.5:7b-instruct`, optional ExpLabs/OpenAI teacher, `alert2attack eval run`.

## Global Constraints

- Python ≥ 3.12, `uv`, package `alert2attack`.
- Default model tag `qwen2.5:7b-instruct`; temperature 0.0 as implemented.
- Gold never enters `CaseStore`.
- Test split is held out: no prompt edits, no graph edits, no training between the three headline runs.
- Never paste scripted smoke numbers into README Results.
- Teacher traffic requires **explicit human approval** (API key + spend). Local 7B / B0 do not.

---

### Task 1: Plumbing smoke (not headline)

**Files:** none (run only).  
**Test:** existing `tests/eval/test_smoke_eval_scripts.py`.

- [x] **Step 1: Confirm harness**

```bash
uv run pytest tests/eval -q
./scripts/smoke_eval.sh --split test --limit 1
```

Expected: pytest pass; a `reports/` JSON exists; stderr notes scripted smoke is oracle-ish.

- [x] **Step 2: Do not copy those numbers into README**

If anyone pastes them, discard. Continue.

---

### Task 2: Live B0 on test (full N)

**Files:** `reports/<date>-b0-test.json` (gitignored).  
**LLM:** Ollama. **Money:** $0.

- [x] **Step 1: Ollama up with default tag**

```bash
ollama list | grep -F qwen2.5:7b-instruct
```

Expected: the tag is present. If missing: `ollama pull qwen2.5:7b-instruct` (large download; human machine).

- [x] **Step 2: Run B0, no limit**

```bash
ALERT2ATTACK_B0_MODEL=ollama uv run alert2attack eval run --arm b0 --split test --out reports
```

`ALERT2ATTACK_B0_MODEL=ollama` is required when a teacher key is in the environment; otherwise `--arm b0`
resolves to the teacher gateway (`docs/RUN.md`) and this stops being the `$0` Ollama baseline.

Expected: N=13 in the printed table. File `reports/YYYY-MM-DD-b0-test.json` with `dataset_hash` and `report.n == 13`.

Kill this arm if Ollama is down or N<13 (AV-skipped scenarios). Log skipped ids; do not silently drop.

---

### Task 3: Live local 7B agent on test (full N)

**Files:** `reports/<date>-agent-local-7b-test.json`.  
**Money:** $0. **Time:** often 1–3 hours.

- [x] **Step 1: Run the product arm** — Lightning Studio T4 (`2026-09-12`). CPU diagnostic stays in `reports/diagnostic-local-7b-cpu/` and is not the headline row.

```bash
uv run alert2attack eval run --arm agent-local-7b --split test --out reports
```

Expected: N=13. JSON includes per-case `verification_status`, `citation_validity_post`, `key_pid_recall`, `action_safe`.

Kill if `budget_exhaustion_rate` > 0.5 (log and stop; that is a graph bug, not a model bug). Read
per-case `details.budget_timed_out` before applying that rule: a slow host trips the 180 s
`Budget.timeout_s`, which `Budget.consume_llm` records as `llm_exhausted`, so exhaustion driven by wall
clock looks identical to a call-cap hit in the aggregate. Timeout-driven exhaustion is a hardware
verdict, not a graph bug — and not a headline row.

---

### Task 4: Teacher arm — **wait for human spend approval**

**Files:** `reports/<date>-agent-teacher-test.json`.  
**Money:** API. **Do not run this step without a human yes.**

Env (from `docs/RUN.md`):

- Preferred: `EXPLABS_API_KEY` + optional `ALERT2ATTACK_TEACHER_MODEL` (`gpt-5.6-luna` default).
- Fallback: `OPENAI_API_KEY` (default model `gpt-4o-mini`).

- [x] **Step 1: Record approval**

Write into the tracker log: who approved, which provider, which model tag, date. If nobody approved, **stop**. Leave the teacher README row as `—`.

- [x] **Step 2: Run teacher**

```bash
uv run alert2attack eval run --arm agent-teacher --split test --out reports
```

Expected: N=13, `report.arm == "agent-teacher"`, `trace.model` matches the env model.

Kill on auth errors or a billable retry loop. Do not rerun the full split “to see if it improves” — that burns money and peeks at test.

---

### Task 5: Render and paste headline table

**Files:** Modify `README.md` Results table only after live JSON exists.

- [x] **Step 1: Render**

```bash
uv run python scripts/render_eval_table.py reports
```

Expected: markdown rows for each live arm. Ignore scripted smoke files if mixed in (delete or move them out of `reports/` first).

- [x] **Step 2: Paste into README**

Replace the `—` cells. Keep columns: Arm, Split, N, Verdict acc, Mean cost, Citation post, Key-pid recall, Action safety.

Reports are keyed `<date>-<arm>-<split>.json`, so a second run of the same arm on the same day
overwrites the first: write variant runs (e.g. a teacher-backed B0) to a different `--out` directory.

- [x] **Step 3: Gate check (do not train)**

Teacher unlocks LoRA/distill **discussion** only if DR-011 holds on official held-out eval:

1. `mean_citation_validity_post(teacher) ≥ mean_citation_validity_post(b0)` **AND** `mean_key_pid_recall(teacher) ≥ mean_key_pid_recall(b0)`
2. Teacher **strictly beats** B0 on **at least one** of: `action_safety_rate` higher, `mean_verdict_cost` lower, `verdict_accuracy` higher

Ties on citation+key_pid alone are **not** enough. Larger N hoping B0 dips is **not** the plan.

Write the inequalities and the `dataset_hash` into `docs/experiments/TRACKER.md` EXP-001 Result / Decision. Truncated `--limit` slices (including the DR-011 N=3 slice) are **not** EXP-001 headline rows.

If the gate **fails**: Decision = debug loop on **dev**, still no LoRA. If it **passes**: discuss only — still no GPU until “Approved for launch” + Deimos cost OK.

---

### Task 6: Update tracker only

- [x] **Step 1:** Fill EXP-001 Result with N, hashes, and the DR-011 gate inequalities.  
- [x] **Step 2:** Do not start EXP-003/004 training. Distill **drafting** is allowed; GPU is not. Distill on **dev** is a later, separately approved spend.

## Out of scope

- Changing `metrics.py`.
- `--export-distill` on **test**.
- `--limit` for README rows.
- New arms (`b0-teacher`, `agent-noplan`, 14B).
- Installing Unsloth or launching training.
