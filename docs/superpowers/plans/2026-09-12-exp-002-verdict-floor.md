# EXP-002 Verdict Floor Implementation Plan

> **For agentic workers:** Implement task-by-task in this session. Steps use checkbox syntax.

**Goal:** Land a deterministic post-verify verdict floor so a cited high-severity ATT&CK technique cannot ship as NEE/suspicious, without touching metrics or re-running official test.

**Architecture:** Pure function `apply_verdict_floor` in `src/alert2attack/agent/verdict_floor.py`. `verify_node` applies it on every `verify_done` path after hydrate. Knowledge-base tactics only; no gold; no alert-rule hydrate.

**Tech Stack:** existing `alert2attack` package, pytest, `KnowledgeBase.load_default()`.

## Global Constraints

- Do not change `src/alert2attack/eval/metrics.py`.
- Do not re-run official `--split test` after the graph edit.
- Do not start LoRA / GPU training / EXP-003 teacher-dev spend.
- Do not edit prompt-contract strings unless a test in `tests/agent/test_prompts.py` requires it (this plan does not).
- Do not invent evidence ids or techniques.
- Python ≥ 3.12, `uv run pytest`.

---

### Task 1: Lock the analysis

**Files:**

- `docs/experiments/DR-2026-09-12-013-exp-002-write-conservatism.md`
- `docs/superpowers/specs/2026-09-12-exp-002-verdict-floor-design.md`
- `docs/experiments/TRACKER.md`

- [x] DR-013 states the cluster (write conservatism + technique omission) from the Lightning T4 per-case table.
- [x] Tracker EXP-002 row moves from “unblocked” to locked with the floor as the lever.

---

### Task 2: Failing unit tests (TDD red)

**Files:** `tests/agent/test_verdict_floor.py`

- [x] Write tests for: NEE + `T1053.005` → malicious; NEE + `T1059.001` only → unchanged; suspicious + `T1218.005` → malicious; likely_benign + high-sev → malicious; malicious unchanged; empty techniques + empty persistence unchanged; nonempty `scope.persistence` floors NEE; unknown technique id does not floor.
- [x] Run `uv run pytest tests/agent/test_verdict_floor.py -q` and confirm import/attribute failure, not an assertion on existing behavior.

---

### Task 3: Minimal floor (TDD green)

**Files:** `src/alert2attack/agent/verdict_floor.py`

- [x] Implement `HIGH_SEV_TACTICS`, `cited_high_severity_tactics`, `apply_verdict_floor`.
- [x] Re-run unit tests until green.

---

### Task 4: Graph wire (TDD)

**Files:** `tests/agent/test_graph_architecture.py`, `src/alert2attack/agent/graph.py`

- [x] Scripted test: investigate calls `lookup_attack_technique` for `T1053.005`, write emits NEE citing `attack-T1053.005`, final verdict is malicious and a trace note mentions `verdict_floor`.
- [x] Scripted test: write emits NEE citing only `T1059.001` / `ev-0004` (no high-sev tactic) and final verdict stays NEE.
- [x] Apply the floor in `verify_node` on passed and degraded `verify_done` exits. Do not overwrite `pre_repair_case_file`.

---

### Task 5: Verify and stop

- [x] `uv run pytest tests/agent tests/verify tests/eval -q`
- [x] `uv run ruff check src/alert2attack/agent tests/agent`
- [x] `uv run mypy src/alert2attack/agent`
- [x] Do **not** run `alert2attack eval run --split test`.
