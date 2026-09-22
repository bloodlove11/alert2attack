# LSASS false-positive ceiling — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cap LSASS-access alerts that lack dump corroboration to `likely_benign` and strip containment so EXP-004’s smoke kill cannot recur.

**Architecture:** Pure predicate on boxed events + alert rule. Graph applies it after the thin-window ceiling. Containment strip is required because `action_safe` is next_actions, not verdict.

**Tech Stack:** Python 3.12, Pydantic, pytest, existing LangGraph verify node.

## Global Constraints

- Do not change `src/alert2attack/eval/metrics.py`.
- Do not loosen DR-012.
- Do not re-run official `--split test`.
- Do not start LoRA / GPU / EXP-004 in this change.
- Do not invent techniques, evidence ids, or pids.
- Never read gold inside the ceiling.
- Ceiling runs **after** `apply_thin_window_ceiling`.

---

### Task 1: Predicate + ceiling

**Files:**
- Create: `src/alert2attack/agent/lsass_fp.py`
- Test: `tests/agent/test_lsass_fp.py`

- [x] Failing unit tests (cap FP, keep dumpert, ignore other rules, strip isolate)
- [x] Implement
- [x] Commit

### Task 2: Graph wire

**Files:**
- Modify: `src/alert2attack/agent/graph.py`
- Test: `tests/agent/test_graph_architecture.py`

- [x] Scripted OTRF: auditpol benign LSASS vs dumpert
- [x] Apply after thin-window
- [x] Commit

### Task 3: Tracker

- [x] TRACKER + DR-013 lever 6 (unmeasured vs official test; scripted proof only)
- [x] Commit
