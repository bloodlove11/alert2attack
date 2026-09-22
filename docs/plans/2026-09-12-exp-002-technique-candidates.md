# EXP-002 Technique Candidates Implementation Plan

Goal: Make fetched ATT&CK technique ids explicit to the write model without automatically converting speculative lookups into findings.

Architecture: A pure helper extracts known `attack-T…` ids from the evidence ledger. `write_node` passes them to a dedicated supported-vs-speculative prompt checklist. Parsed `CaseFile` output is never mutated by this lever.

Tech Stack: Python 3.12, Pydantic domain models, LangGraph, pytest, Ruff, mypy.

## Global Constraints

- Do not change `src/alert2attack/eval/metrics.py`.
- Do not run `alert2attack eval run --split test`.
- Do not call a live model or spend teacher API budget.
- Do not automatically add `TechniqueClaim` objects.
- Do not derive techniques from `rule-*` ids or alert metadata.
- Do not start LoRA / GPU training.

### Task 1: Candidate extraction

Files:
- Create: `src/alert2attack/agent/technique_candidates.py`
- Test: `tests/agent/test_technique_candidates.py`

- [x] Write failing tests for exact `attack-T…` extraction, sort/dedup,
      unknown ids, and event/rule/malformed exclusions.
- [x] Run the focused test and observe failure because the module is absent.
- [x] Implement the minimal pure helper.
- [x] Run the focused test green.

### Task 2: Prompt contract

Files:
- Modify: `src/alert2attack/agent/prompts.py`
- Modify: `tests/agent/test_prompts.py`

- [x] Write a failing test proving candidate ids and matched evidence ids are
      shown, and language says candidates are not automatic findings.
- [x] Add `attack_technique_candidates` to `write_user`.
- [x] State that supported candidates become claims, speculative candidates
      are omitted, and `rule-*` alone is never projected.
- [x] Run prompt tests green.

### Task 3: Graph wiring

Files:
- Modify: `src/alert2attack/agent/graph.py`
- Modify: `tests/agent/test_graph_architecture.py`

- [x] Write a failing scripted test where `lookup_attack_technique` adds
      `attack-T1053.005` and the write call receives `T1053.005`.
- [x] Write a scripted safety test where the writer omits that candidate and
      the final case still has no technique and remains NEE.
- [x] Wire helper output into `write_user`.
- [x] Run graph tests green.

### Task 4: Decision docs

Files:
- Modify: `docs/experiments/DR-2026-09-12-013-exp-002-write-conservatism.md`
- Modify: `docs/experiments/TRACKER.md`
- Modify: `README.md`

- [x] Record lever 2 as implemented (initially not live-dev measured).
- [x] Record why deterministic projection was rejected.
- [x] Preserve pre-floor EXP-001 headline numbers and no-launch language.
- [x] After merge: record Lightning T4 dev 3-case wiring smoke in DR-013 /
      TRACKER / README (no accuracy claim, no official test).

### Task 5: Verification and delivery

- [x] Run `uv run pytest tests`.
- [x] Run `uv run ruff check .`.
- [x] Run `uv run mypy`.
- [x] Confirm `src/alert2attack/eval/metrics.py` is unchanged.
- [x] Commit, push, and open a ready PR against `main`.

### Task 6: Live-dev wiring smoke (post-merge docs)

- [x] Run three dev controls on Lightning T4 (`qwen2.5:7b-instruct`).
- [x] Confirm candidates / `- none` / no false projection / no execution-only floor lift.
- [x] Stop Studio; keep artifacts under
      `reports/diagnostic-exp002-technique-candidates/` (gitignored).
- [x] Document outcomes; do not overwrite README Results headline table.
