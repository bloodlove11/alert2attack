# Phase 3 — LangGraph Investigation Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (or subagent-driven-development) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a local-first investigation agent that plans, calls the Phase-1 tool surface under budgets, and writes a structured `CaseFile` + `Trace`, driven by `ScriptedChat` in CI and `OllamaChat` (`qwen2.5:7b-instruct`) by default.

**Architecture:** `alert2attack.domain` gains the output `CaseFile` models. `alert2attack.agent` owns `ChatModel` (Scripted / Ollama / OpenAI teacher), budgets, traces, prompts, and a LangGraph `plan → investigate → write` graph. The agent never holds a `CaseStore`; it only calls `ToolRegistry` through a `ToolContext`. Verifier/repair is **Phase 4** — Phase 3 returns `verification=None`.

**Tech Stack:** Python 3.12, Pydantic v2, LangGraph, OpenAI Python SDK (Ollama `/v1` + teacher), Typer, pytest. No live LLM in CI.

## Global Constraints

- RTX 4060 8 GB → default model `qwen2.5:7b-instruct` (not 14B).
- Tools never raise into the agent; failures are `ToolResult(ok=False)`.
- Gold never enters `CaseStore`.
- Default budgets: `max_tool_calls=12`, `max_llm_calls=20`, `timeout_s=180`.
- CI uses `ScriptedChat` only; live tests gated by `ALERT2ATTACK_LIVE=1`.

---

### Task 1: CaseFile domain models

**Files:**
- Create: `src/alert2attack/domain/casefile.py`
- Modify: `src/alert2attack/domain/__init__.py` (optional re-exports)
- Test: `tests/domain/test_casefile.py`

**Interfaces:**
- Produces: `Verdict`, `NextAction`, `Claim`, `TimelineEntry`, `TechniqueClaim`, `Scope`, `ActionRecommendation`, `CaseFile`

- [ ] **Step 1: Write failing tests** for round-trip validation and non-empty claim evidence.

- [ ] **Step 2: Implement models** matching design §5.3 (`Verdict` includes `SUSPICIOUS`; gold never uses it).

- [ ] **Step 3: pytest + commit** `feat(domain): CaseFile output models`

---

### Task 2: Budgets + Trace

**Files:**
- Create: `src/alert2attack/agent/budget.py`, `src/alert2attack/agent/trace.py`, `src/alert2attack/agent/__init__.py`
- Test: `tests/agent/test_budget.py`, `tests/agent/test_trace.py`

**Interfaces:**
- Produces: `Budget(max_tool_calls=12, max_llm_calls=20, timeout_s=180)` with `consume_tool()` / `consume_llm()` / `exhausted` flags; `Trace` appending `LlmCallRecord` and reusing `ToolCallRecord` from the ledger snapshot.

- [ ] **Step 1–4: TDD** budget exhaustion and trace serialization to JSON.

- [ ] **Step 5: Commit** `feat(agent): budgets and investigation traces`

---

### Task 3: ChatModel + ScriptedChat (+ Ollama / OpenAI clients)

**Files:**
- Create: `src/alert2attack/agent/llm.py`
- Test: `tests/agent/test_scripted_chat.py`
- Modify: `pyproject.toml` — add `langgraph`, `openai`

**Interfaces:**
- Produces: `ChatMessage`, `ToolCallRequest`, `ChatResponse`, `ChatModel` protocol; `ScriptedChat`, `OllamaChat` (base `http://127.0.0.1:11434/v1`, model `qwen2.5:7b-instruct`), `OpenAIChat` (teacher ablation).

- [ ] **Step 1: ScriptedChat** pops scripted `ChatResponse`s (content and/or tool_calls).

- [ ] **Step 2: OllamaChat / OpenAIChat** via OpenAI SDK against compatible base URLs; temperature 0.

- [ ] **Step 3: Commit** `feat(agent): ChatModel protocol with Scripted/Ollama/OpenAI`

---

### Task 4: LangGraph plan → investigate → write

**Files:**
- Create: `src/alert2attack/agent/prompts.py`, `src/alert2attack/agent/graph.py`, `src/alert2attack/agent/investigator.py`
- Test: `tests/agent/test_investigator.py` (ScriptedChat scripted path on fixture scenario)

**Interfaces:**
- Consumes: `ToolRegistry`, `ToolContext`, `ChatModel`, `Budget`
- Produces: `Investigator.run(scenario|case_id) -> InvestigationResult(case_file, trace, verification=None)`

Graph:
1. **plan** — LLM returns short plan text (hypotheses + first tools).
2. **investigate** — tool-calling loop until no tool calls or budget exhausted (`max_tool_calls`).
3. **write** — LLM returns JSON `CaseFile`; parse with Pydantic; on parse failure, one retry then a minimal degraded file with `open_questions`.

- [ ] **Step 1: Scripted end-to-end** — plan → `get_alert` → `get_process_tree` → write malicious CaseFile citing ledger ids.

- [ ] **Step 2: Budget stop** — ScriptedChat keeps requesting tools after budget → investigate stops.

- [ ] **Step 3: Commit** `feat(agent): LangGraph plan/investigate/write Investigator`

---

### Task 5: CLI `alert2attack investigate`

**Files:**
- Modify: `src/alert2attack/cli.py`, `README.md`
- Test: `tests/test_cli_investigate.py`

- [ ] **Step 1: Command** `alert2attack investigate <scenario_id> [--model scripted|ollama|openai] [--max-tools N]` prints CaseFile JSON + trace summary.

- [ ] **Step 2: Scripted path** in tests (no network).

- [ ] **Step 3: Commit** `feat(cli): alert2attack investigate`

---

### Task 6: Verify package + PR

- [ ] `uv run pytest && uv run ruff check . && uv run mypy`
- [ ] Push + update PR #4 body for Phase 3

## Out of this phase (Phase 4+)

- Deterministic verifier + repair ≤2 + degrade
- Eval harness / B0 / arms
- FastAPI / Compose

## Spec coverage

| Spec § | Task |
|---|---|
| 5.3 CaseFile | 1 |
| 5.5 graph (plan/investigate/write), ChatModel, budgets | 2–4 |
| 5.5 verify/repair | deferred → Phase 4 |
| CLI investigate | 5 |
| CI ScriptedChat only | 3–5 |
