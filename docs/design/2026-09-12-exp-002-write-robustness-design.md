# EXP-002 write robustness: design

Status: Approved by "pr approved go next" after lever-2 live-dev smoke.  
Date: 2026-09-12  
Related: `docs/experiments/DR-2026-09-12-013-exp-002-write-conservatism.md`

## Problem

Lever-2 wiring is correct, but the Lightning T4 dev smoke showed write still
fails before candidates can help:

1. Malicious twin: wall-clock timeout during investigate → write never recorded a
   real LLM call (`llm_exhausted`/`timed_out` with only investigate roles).
2. NEE twin: write ran, but CaseFile JSON had extras (`case_id`, `case_name`) and
   missing `confidence` → both validation attempts failed → degraded NEE.

Without a successful parse, technique candidates and the verdict floor cannot
act. This is still a graph lever, not LoRA.

## Approaches

1. Reserve write budget + normalize CaseFile JSON (chosen). Stop investigate
   while ≥2 LLM calls and ≥60s wall time remain. Before `CaseFile` validation,
   strip known-harmless extras and default missing `confidence` to `low` when a
   `verdict` is present. Never invent techniques, evidence, or verdicts.
2. Raise global timeout / max_llm only (rejected as primary). Masks the
   starvation bug and burns more T4 time without guaranteeing write.
3. Loosen `CaseFile` to `extra=ignore` globally (rejected). Hides schema
   drift everywhere; prefer an explicit write/repair normalizer.
4. Automatic technique projection (still rejected). Same NEE-twin hazard as
   lever 2.

## Design

### Budget reservation

Add `Budget.remaining_time_s()`. Investigate stops when:

- `remaining_llm() <= WRITE_LLM_RESERVE` (default 2), or
- `remaining_time_s() <= WRITE_TIME_RESERVE_S` (default 60),

in addition to existing tool/timeout/max-turn stops. Trace note:
`investigate: stop (reserve write budget/time)`.

Write short-circuits to the degraded CaseFile when the first write response is
`BUDGET_EXHAUSTED` / empty of JSON: do not spend the reserved retry on a dead
budget.

### CaseFile JSON normalization

`normalize_casefile_dict(payload) -> dict` (pure):

- Drop unknown top-level keys (`case_id`, `case_name`, etc.).
- Optional alias: `description` → `summary` only if `summary` absent.
- If `verdict` present and `confidence` absent → set `"low"`.
- Do not invent `techniques`, `timeline`, evidence ids, or `verdict`.

Used by write (and repair) after `extract_json_object`, before
`CaseFile.model_validate`.

## Validation and protocol

- Unit-test reservation math and normalizer behavior.
- Scripted graph: investigate stops with LLM/time left for write; messy JSON with
  extras still parses; rejection path (no techniques invented) unchanged.
- Do not change `src/alert2attack/eval/metrics.py`.
- Do not run official `--split test`.
- No teacher API spend, no LoRA/GPU, no launch claim.
