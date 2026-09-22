# EXP-002 Write Robustness Implementation Plan

Goal: Reserve LLM/wall-clock budget for write and tolerate common 7B CaseFile JSON extras so lever 2 can run.

Architecture: Budget helpers expose remaining wall time; investigate stops early to preserve a write reserve. A pure normalizer strips unknown CaseFile keys and defaults missing confidence before validation. No automatic technique projection; metrics and official test untouched.

Tech Stack: Python 3.12, Pydantic CaseFile, LangGraph, pytest, Ruff, mypy.

## Global Constraints

- Do not change `src/alert2attack/eval/metrics.py`.
- Do not run `alert2attack eval run --split test`.
- Do not call a live teacher model or spend API budget.
- Do not automatically add technique claims.
- Do not start LoRA / GPU training.

### Task 1: Budget write reserve

Files:
- Modify: `src/alert2attack/agent/budget.py`
- Modify: `tests/agent/test_budget.py`

- [x] Add failing tests for `remaining_time_s()` and "investigate must stop when only write reserve remains" helpers (or document constants used by graph).
- [x] Implement `remaining_time_s()` on `Budget`.
- [x] Run budget tests green.

### Task 2: CaseFile JSON normalizer

Files:
- Modify: `src/alert2attack/agent/jsonutil.py` (or new small module if cleaner)
- Test: `tests/agent/test_jsonutil.py` (create if absent)

- [x] Failing tests: strip `case_id`/`case_name`; default missing `confidence` to `low` when verdict present; do not invent techniques/verdict; `description`→`summary` alias only when needed.
- [x] Implement `normalize_casefile_dict`.
- [x] Tests green.

### Task 3: Graph wiring

Files:
- Modify: `src/alert2attack/agent/graph.py`
- Modify: `tests/agent/test_graph_architecture.py`

- [x] Failing test: investigate stops while ≥2 LLM calls remain when near reserve.
- [x] Failing test: write accepts JSON with extras + missing confidence via normalizer.
- [x] Wire stop condition + normalize in write (and repair if it validates JSON the same way).
- [x] Short-circuit write when first output is budget-exhausted / no JSON.
- [x] Graph tests green.

### Task 4: Decision docs

Files:
- Modify: `docs/experiments/DR-2026-09-12-013-exp-002-write-conservatism.md`
- Modify: `docs/experiments/TRACKER.md`
- Modify: `README.md` (narrative only; no Results table overwrite)

- [x] Record lever 3 as implemented with scripted coverage; no live accuracy claim yet.
- [x] Preserve EXP-001 headline numbers and no-launch language.

### Task 5: Verification and delivery

- [x] `uv run pytest tests`
- [x] `uv run ruff check .`
- [x] `uv run mypy`
- [x] Confirm `src/alert2attack/eval/metrics.py` unchanged
- [x] Commit, push, open ready PR against `main`

### Task 6: Live-dev wiring smoke (post-merge docs)

- [x] Run three dev controls on Lightning T4 with adequate timeout.
- [x] Confirm write can run / normalize / no false projection.
- [x] Stop Studio; keep artifacts under `reports/diagnostic-exp002-write-robustness/` (gitignored).
- [x] Document outcomes; do not overwrite README Results headline table.
