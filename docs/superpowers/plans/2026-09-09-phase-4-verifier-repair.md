# Phase 4 — Verifier + Repair + Degrade Implementation Plan

> **For agentic workers:** Implement task-by-task. Steps use checkbox syntax.

**Goal:** Enforce citation faithfulness: every CaseFile claim must cite ledger evidence; repair ≤2 via LLM; otherwise strip unsupported claims and mark degraded.

**Architecture:** Pure `alert2attack.verify.verify(...)` over `(CaseFile, EvidenceLedger, CaseStore, KnowledgeBase)`. LangGraph extends to `write → verify ⇄ repair (≤2) → [degrade] → END`. `InvestigationResult.verification` is always a `VerificationReport`.

**Tech Stack:** Existing agent stack; no new deps.

## Global Constraints

- Stable error codes: `UNKNOWN_EVIDENCE`, `EVIDENCE_NOT_IN_LEDGER`, `PID_UNSUPPORTED`, `UNKNOWN_TECHNIQUE`, `TIMELINE_UNSORTED`, `SUMMARY_TOO_LONG`, `EMPTY_EVIDENCE`
- Fabricated claims never leave clean (`status != "passed"` if stripped)
- Fine-tuning remains out of scope (design §9)

---

### Task 1: Verifier + degrade

**Files:** `src/alert2attack/verify/{__init__,models,verify,degrade}.py`, `tests/verify/test_verify.py`

### Task 2: Graph verify/repair nodes

**Files:** `src/alert2attack/agent/graph.py`, `prompts.py`, `investigator.py`

### Task 3: CLI + docs + PR

Wire verification into `alert2attack investigate` output; update README phase marker.
