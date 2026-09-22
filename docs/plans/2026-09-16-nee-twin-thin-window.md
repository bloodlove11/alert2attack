# NEE-twin thin-window abstain — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (inline). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cap writes on boxed trigger-only windows to `not_enough_evidence` so NEE twins are not labeled malicious, without dropping full-window gold-malicious keeps or loosening DR-012.

**Architecture:** Pure predicate + ceiling on boxed `CaseStore` events. Graph applies it after the EXP-002 verdict floor so a cited T1218 cannot lift a truncated twin. Catalog invariant locks the thin=NEE-twin construction.

**Tech Stack:** Python 3.12, Pydantic, pytest, existing LangGraph verify node.

## Global Constraints

- Do not change `src/alert2attack/eval/metrics.py`.
- Do not loosen DR-012 or `--prefer-correct-verdict`.
- Do not re-run official `--split test`.
- Do not start LoRA / GPU / EXP-004 in this change.
- Do not invent verdict, techniques, evidence ids, or pids.
- Do not rewrite `next_actions`.
- Never read gold inside the ceiling.
- Ceiling runs **after** `apply_verdict_floor`.

---

### Task 1: Thin-window predicate and ceiling

**Files:**
- Create: `src/alert2attack/agent/thin_window.py`
- Test: `tests/agent/test_thin_window.py`

**Interfaces:**
- Produces: `is_thin_trigger_window(events: Sequence[Event]) -> bool`, `apply_thin_window_ceiling(case_file: CaseFile, events: Sequence[Event]) -> CaseFile`, `CEILING_NOTE: str`

- [ ] **Step 1: Write the failing tests**

```python
from alert2attack.agent.thin_window import apply_thin_window_ceiling, is_thin_trigger_window
from alert2attack.agent.verdict_floor import apply_verdict_floor
from alert2attack.domain.casefile import CaseFile, TechniqueClaim, Verdict
from alert2attack.domain.events import Event, EventKind
from alert2attack.knowledge.base import KnowledgeBase

def _pc(eid: str, pid: int) -> Event:
    return Event(
        event_id=eid,
        kind=EventKind.PROCESS_CREATE,
        ts="2020-10-22T06:21:37.849000Z",
        host="WORKSTATION5",
        pid=pid,
        image="C:\\Windows\\System32\\mshta.exe",
    )

def test_one_or_two_process_creates_are_thin() -> None:
    assert is_thin_trigger_window([_pc("ev-0001", 10076)]) is True
    assert is_thin_trigger_window([_pc("ev-0001", 10196), _pc("ev-0002", 10076)]) is True

def test_empty_or_followon_is_not_thin() -> None:
    assert is_thin_trigger_window([]) is False
    load = Event(
        event_id="ev-0002",
        kind=EventKind.IMAGE_LOAD,
        ts="2020-10-22T06:21:37.849000Z",
        host="WORKSTATION5",
        pid=10076,
        image="C:\\Windows\\System32\\mshta.exe",
        target_path="C:\\Windows\\System32\\ntdll.dll",
    )
    assert is_thin_trigger_window([_pc("ev-0001", 10076), load]) is False

def test_ceiling_caps_malicious_on_thin_window() -> None:
    cf = CaseFile(verdict="malicious", confidence="high", summary="Mshta proxy execution observed.")
    out = apply_thin_window_ceiling(cf, [_pc("ev-0001", 10076)])
    assert out.verdict is Verdict.NOT_ENOUGH_EVIDENCE
    assert any("trigger" in q.lower() for q in out.open_questions)

def test_ceiling_beats_verdict_floor_on_thin_t1218() -> None:
    kb = KnowledgeBase.load_default()
    cf = CaseFile(
        verdict="not_enough_evidence",
        confidence="low",
        summary="Mshta proxy execution observed.",
        techniques=[TechniqueClaim(technique_id="T1218.005", evidence=["attack-T1218.005"])],
    )
    floored = apply_verdict_floor(cf, kb)
    assert floored.verdict is Verdict.MALICIOUS
    out = apply_thin_window_ceiling(floored, [_pc("ev-0001", 10076)])
    assert out.verdict is Verdict.NOT_ENOUGH_EVIDENCE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/agent/test_thin_window.py -q`

Expected: FAIL (`thin_window` not defined)

- [ ] **Step 3: Implement predicate + ceiling**

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/agent/test_thin_window.py -q`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/alert2attack/agent/thin_window.py tests/agent/test_thin_window.py
git commit -m "feat(agent): cap thin trigger-only windows to NEE"
```

---

### Task 2: Catalog invariant + graph wire

**Files:**
- Modify: `src/alert2attack/agent/graph.py` (`_apply_verdict_floor` → floor then ceiling)
- Test: `tests/agent/test_thin_window.py` (catalog), `tests/agent/test_graph_architecture.py`

**Interfaces:**
- Consumes: `apply_thin_window_ceiling`, `CaseStore.query_events(case_id, limit=1000)`
- Produces: trace note `thin_window: <old> → not_enough_evidence`

- [ ] **Step 1: Failing catalog + graph tests**

Catalog: every `*_nee` scenario with gold `not_enough_evidence` is thin; no gold-malicious scenario is thin.

Graph: scripted write of malicious+`T1218.005` citing `ev-0001` / `attack-T1218.005` on `otrf_cmd_mshta_javascript_getobject_sct_nee` ends NEE with a `thin_window` note. Same write on `otrf_cmd_mshta_javascript_getobject_sct` stays malicious.

- [ ] **Step 2: Run tests (expect FAIL on graph wire)**

- [ ] **Step 3: Apply ceiling after floor in `verify_node` passed and degraded exits**

- [ ] **Step 4: Run `uv run pytest tests/agent tests/dataset tests/domain -q`**

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/alert2attack/agent/graph.py tests/agent/test_graph_architecture.py tests/agent/test_thin_window.py
git commit -m "feat(agent): apply thin-window ceiling after verdict floor"
```

---

### Task 3: Tracker note (pre-measure)

**Files:**
- Modify: `docs/experiments/TRACKER.md`, `docs/experiments/DR-2026-09-12-013-exp-002-write-conservatism.md`

Record lever 5 as implemented, scripted-only, **not** a measured n_kept. Do not paste a counterfactual 14 as a live card.

- [ ] **Step 1: Write the tracker / DR-013 lever-5 section**
- [ ] **Step 2: Commit**

```bash
git add docs/experiments/TRACKER.md docs/experiments/DR-2026-09-12-013-exp-002-write-conservatism.md
git commit -m "docs: record EXP-002 lever 5 thin-window abstain (unmeasured)"
```
