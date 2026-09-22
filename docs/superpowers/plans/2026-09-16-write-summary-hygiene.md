# Write-path summary hygiene — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep teacher writes that fail only because `.exe` / `T1218.005` / hostnames inflate `summary.count(".")`, without loosening the 3-sentence cap or DR-012.

**Architecture:** One shared `summary_sentence_count` used by `CaseFile` validation and `verify`. `normalize_casefile_dict` clips *real* overflow to 3 sentences so write/repair does not discard the CaseFile. Graph already calls `parse_case_file`.

**Tech Stack:** Python 3.12, Pydantic, pytest, existing LangGraph write node.

## Global Constraints

- Do not change `src/alert2attack/eval/metrics.py`.
- Do not loosen DR-012 or `--prefer-correct-verdict`.
- Do not re-run official `--split test`.
- Do not start LoRA / GPU / EXP-004.
- Do not invent verdict, techniques, evidence ids, or pids.
- Cap remains 3 **real** sentences (`SUMMARY_TOO_LONG` stays).

---

### Task 1: Domain sentence counter

**Files:**
- Modify: `src/alert2attack/domain/casefile.py`
- Test: `tests/domain/test_casefile.py`

**Interfaces:**
- Produces: `MAX_SUMMARY_SENTENCES: int = 3`, `summary_sentence_count(text: str) -> int`, `clip_summary_sentences(text: str, *, max_sentences: int = 3) -> str`

- [ ] **Step 1: Write the failing tests**

```python
from pydantic import ValidationError
from alert2attack.domain.casefile import CaseFile, clip_summary_sentences, summary_sentence_count

TEACHER_MSHTA_RETRY = (
    "mshta.exe executed inline JavaScript that retrieved and invoked a remote "
    "scriptlet, matching T1218.005 proxy execution. The activity occurred on "
    "WORKSTATION5 under WORKSTATION5\\wardog and used the referenced Atomic "
    "Red Team payload."
)

def test_teacher_mshta_retry_is_two_sentences_not_four_periods() -> None:
    assert TEACHER_MSHTA_RETRY.count(".") == 4
    assert summary_sentence_count(TEACHER_MSHTA_RETRY) == 2
    CaseFile(verdict="malicious", confidence="high", summary=TEACHER_MSHTA_RETRY)

def test_four_real_sentences_still_rejected() -> None:
    text = "One claim. Two claim. Three claim. Four claim."
    assert summary_sentence_count(text) == 4
    try:
        CaseFile(verdict="suspicious", confidence="low", summary=text)
    except ValidationError:
        return
    raise AssertionError("expected ValidationError")

def test_clip_keeps_first_three_real_sentences() -> None:
    text = "One claim. Two claim. Three claim. Four claim."
    assert clip_summary_sentences(text) == "One claim. Two claim. Three claim."
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/domain/test_casefile.py -q`
Expected: FAIL (`summary_sentence_count` not defined / ValidationError on teacher string)

- [ ] **Step 3: Implement counter + clip + validator**

Add the helpers in `casefile.py`. Validator uses `summary_sentence_count` instead of `text.count(".")`.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/domain/test_casefile.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/alert2attack/domain/casefile.py tests/domain/test_casefile.py
git commit -m "feat(domain): count real summary sentences, not .exe periods"
```

---

### Task 2: Normalizer clip + parse

**Files:**
- Modify: `src/alert2attack/agent/jsonutil.py`
- Test: `tests/agent/test_jsonutil.py`

- [ ] **Step 1: Failing tests** — `parse_case_file` accepts teacher mshta JSON; `normalize_casefile_dict` clips four real sentences without changing `verdict` / `techniques`.

- [ ] **Step 2: Run** `uv run pytest tests/agent/test_jsonutil.py -q` — FAIL until clip is wired.

- [ ] **Step 3: Clip `summary` inside `normalize_casefile_dict`.**

- [ ] **Step 4: PASS + commit** `fix(agent): clip overlong CaseFile summaries instead of discarding the write`

---

### Task 3: Verifier uses the same counter

**Files:**
- Modify: `src/alert2attack/verify/verify.py`
- Test: `tests/verify/test_verify.py`

- [ ] Teacher-style two-sentence summary with `.exe` + `T1218.005` does **not** emit `SUMMARY_TOO_LONG`.
- [ ] Four real sentences still emit `SUMMARY_TOO_LONG`.
- Commit: `fix(verify): ignore non-sentence periods in SUMMARY_TOO_LONG`

---

### Task 4: Scripted graph — keep the write

**Files:**
- Test: `tests/agent/test_graph_architecture.py`

- [ ] Write JSON whose summary is the teacher mshta retry string, citing `ev-0004`, verdict malicious → result is **not** the NEE stub; no `parse failed twice`.
- [ ] Four-real-sentence summary still yields a CaseFile (clipped), not a parse-fail stub.
- Commit with graph test only (no production graph change expected; `parse_case_file` already used).

---

### Task 5: Docs

**Files:**
- Modify: `docs/experiments/TRACKER.md`, `docs/experiments/DATA_CARD-teacher-dev-v0.md`, `docs/experiments/DR-2026-09-12-013-exp-002-write-conservatism.md`

Record lever 4. Measured 2026-09-16 re-export: n_kept stayed **11** (mshta gold kept; counterfactual 12 did not hold). **Not** a launch.
