# alert2attack: sourced case files from EDR alerts

Design spec, 2026-09-09 (revised). Status: approved for implementation planning.  
Companion plan: `docs/plans/2026-09-09-phase-1-case-store-and-tools.md` (Phase 1 unchanged; later phases get their own plans).

## 0. Why this document exists

Goal. Build the investigation loop an EDR product needs, end to end: plan, call tools over endpoint telemetry, write a reliable sourced case, measure it, and package it to run, with a local model as the default. The object is what happens after an alert fires, and the aim is to find out where such a loop breaks. Success means the loop is measured and its failure modes are known.

Revision note. An earlier draft targeted seven phases including LoRA distillation and a case UI, with `qwen2.5:14b` as default and ~40 scenarios. After feasibility analysis (RTX 4060 mobile 8 GB VRAM, i9-13980HX, 32 GB RAM) and related-work research, v1 is cut to what one person can build and measure on this machine. Fine-tuning and UI are out of scope for this project.

## 1. Capability map

| Capability an EDR investigation loop needs | Common gap in LLM projects | Where it lives in this repo |
|---|---|---|
| Investigation agent (plan, tool calling, synthesis) | Classification, RAG and CVE-to-ATT&CK work is not EDR case work | LangGraph: plan → budgeted tools → write → verify |
| Eval framework + metrics over time | Faithfulness and a baseline are often missing | `alert2attack eval`, arms, reports, README table |
| Open-source and proprietary trade-offs | Cloud-only production path | Local 7B default + proprietary teacher ablation |
| Industrialize (tests, packaging, docs, CI/CD) | A deployed demo is not measured product behavior | pytest, ruff, mypy, Compose, GitHub Actions CI |
| Deploy + monitor | No long-lived signals | Thin FastAPI + Prometheus + structured logs |
| Own an ambiguous topic | n/a | This spec: critique, cuts, locked interfaces |
| Fine-tuning / LLM internals | Secondary to the loop itself | Out of v1, short "why not / how later" only (§9) |

Python, security and LangGraph basics are assumed and not rebuilt here.

## 2. What stays from the original thesis

- The object is the investigation loop, not detection.
- The agent sees only what an analyst sees; gold is held out.
- Output is a case file, not a chat: structured, sourced, verdict + next actions.
- Tools are boxed to host + time window.
- Next actions are recommend-only (never execute).
- Evidence ledger + deterministic verifier: hallucination is a measured number.
- B0 baseline (single prompt, all window events inlined): agent must beat B0 on citation validity and scope recall or the design is wrong.

## 3. Approaches considered

A. Single-shot structured prompt (no tools). Kept only as baseline B0.

B. One LangGraph agent: plan, tool loop, write, verify/repair. (Chosen.) Small tool surface, works with 7B local models, ablatable node-by-node.

C. Multi-agent (planner / hunter / writer / critic). Rejected: worse with small local models; verifier already plays critic deterministically for citation validity.

## 4. Related work (what we steal, what we don't)

| Work | Steal | Reject |
|---|---|---|
| [VERDICT](https://github.com/TimothyVang/verdict-dfir-beta), [LogPoseSIFT](https://github.com/amareshhebbar/LogPoseSIFT) | Typed tools only; no shell; tools never raise into the agent: errors are data (`ToolResult.ok == False`) | MCP sprawl, memory/YARA/full DFIR surface, crypto custody |
| [ExCyTIn-Bench](https://arxiv.org/abs/2507.14201) (Microsoft) | Score process, not only final answer: citation validity before and after repair | Azure SQL over 57 tables; Q&A instead of a case file |
| [ApexHunter](https://github.com/laithSamara/ApexHunter) | Offline / sovereign framing | Playbook+SQL executor as the whole product |
| [Cyber Defense Benchmark](https://arxiv.org/abs/2604.19533) | OTRF as provenance for real Windows telemetry | Alert-free open hunt (we stay alert-seeded, product-shaped) |
| Typical LangGraph "SOC multi-agent" demos | Recommend-only / HITL posture | Multi-agent + fake alerts + no faithfulness metric |

Positioning: alert-driven EDR investigation + analyst-shaped tools + evidence ledger + deterministic citation verifier + B0 + local-default / proprietary ablation. That combination is rare; we do not clone any of the above.

## 5. Architecture

```
alert + boxed telemetry ──▶ CaseStore (SQLite, one case = one host + one window)
                                  │
                       sandboxed tools (only way to read the store; no shell)
                                  │  every returned event carries an evidence id
                                  ▼
                          EvidenceLedger (ids seen in THIS run)
                                  │
   LangGraph:  plan ─▶ investigate (tool loop, budgeted) ─▶ write ─▶ verify ─▶ [repair ≤2] ─▶ CaseFile + Trace
                                                                        │
                                                    deterministic: every claim cites ≥1 ledger id,
                                                    pids exist, technique ids valid, enums valid
```

### 5.1 Units and boundaries

| Unit | Responsibility | Depends on | Public interface (stable) |
|---|---|---|---|
| `alert2attack.domain` | Pydantic models: `Event`, `EventKind`, `Alert`, `Scenario`, `Gold`, `CaseFile`, `Claim`, evidence-id grammar | pydantic | Models only, no I/O |
| `alert2attack.store` | `CaseStore`: load a scenario's *public* part into SQLite; scoped queries | domain, sqlite3 | `load_case`, `get_alert`, `get_window`, `get_event`, `find_process`, `children`, `query_events` |
| `alert2attack.knowledge` | Vendored Sigma rules (YAML) and ATT&CK technique subset (JSON); PowerShell decoder | pyyaml | `KnowledgeBase.rule(slug)`, `.technique(id)`, `decode_powershell(cmdline)` |
| `alert2attack.tools` | `ToolContext`, `EvidenceLedger`, `ToolResult`, `ToolRegistry`; the tool functions | store, knowledge | `registry.openai_schemas()`, `registry.call(ctx, name, args) -> ToolResult` |
| `alert2attack.agent` | LangGraph graph, LLM client abstraction, prompts, budgets, trace recording | tools, langgraph, openai | `Investigator.run(case_id) -> InvestigationResult(case_file, trace, verification)` |
| `alert2attack.verify` | Deterministic `verify(case_file, ledger, store) -> VerificationReport` | domain, tools | Pure function |
| `alert2attack.eval` | Scenario splits, runner, metrics (incl. pre/post citation), B0, report | agent, store | `alert2attack eval run --arm <name> --split test` |
| `alert2attack.api` | FastAPI: `POST /investigations`, `GET /investigations/{id}`, `GET /metrics` | agent, prometheus-client | HTTP |
| `alert2attack.cli` | Typer CLI for tools, investigate, eval, dataset build | all | Shell |

Rules:

- Only `alert2attack.tools` may read `CaseStore` during an investigation. The agent never receives a store handle.
- Gold never enters `CaseStore` (test-enforced; SQLite must contain no gold text).
- Tools never invoke a shell. The registry never raises into the agent; failures are `ToolResult(ok=False, error=...)`.

### 5.2 Data model (domain)

Normalized event, ECS-flavoured, flat, one row per telemetry event:

| `EventKind` | Source | Key fields |
|---|---|---|
| `process_create` | Sysmon 1 | pid, ppid, image, command_line, parent_image, sha256, user |
| `network_connect` | Sysmon 3 | pid, image, dest_ip, dest_port, dest_host |
| `image_load` | Sysmon 7 | pid, image, target_path, sha256 |
| `process_access` | Sysmon 10 | pid, image, target_pid, target_image, details |
| `file_create` | Sysmon 11 | pid, image, target_path |
| `registry_set` | Sysmon 13 | pid, image, target_path, details |
| `dns_query` | Sysmon 22 | pid, image, query |
| `service_install` | System 7045 | details |
| `scheduled_task` | Security 4698 | user, details |

Evidence ids: `ev-NNNN` (scenario-stable), `rule-<slug>`, `attack-T####[.###]`. Grammar (single regex in `alert2attack.domain.evidence`):

```text
^(ev-\d{4,}|rule-[a-z0-9_\-]+|attack-T\d{4}(\.\d{3})?)$
```

`Scenario` = `scenario_id`, `split` (`dev|test`), `origin` (`otrf|authored`), `window`, `alert`, `events`, `gold: Gold | None`. `Scenario.public()` strips gold; `CaseStore.load_case` accepts only the public form.

### 5.3 Case file (output)

```python
class Verdict(StrEnum): MALICIOUS, SUSPICIOUS, LIKELY_BENIGN, NOT_ENOUGH_EVIDENCE
class NextAction(StrEnum): ISOLATE_HOST, KILL_PROCESS, COLLECT_SCRIPT, COLLECT_MEMORY,
                           BLOCK_HASH, RESET_CREDENTIALS, ESCALATE, MONITOR, CLOSE_AS_BENIGN

class Claim(BaseModel):
    text: str
    evidence: list[EvidenceId]   # non-empty; verified against the ledger

class CaseFile(BaseModel):
    verdict: Verdict
    confidence: Literal["low", "medium", "high"]
    summary: str                                 # ≤ 3 sentences
    timeline: list[TimelineEntry]
    techniques: list[TechniqueClaim]
    scope: Scope                                 # root_process, involved_pids, persistence, beyond_process
    next_actions: list[ActionRecommendation]     # closed NextAction vocab + Claim rationale
    open_questions: list[str]                    # honest abstention beats guessing
```

### 5.4 Tools (v1 surface)

| Tool | Notes |
|---|---|
| `get_alert` | Always the natural first call |
| `get_process` | Boxed to case |
| `get_process_tree` | `depth≤4`, fan-out ≤50 |
| `get_events_for_process` | Paginated |
| `search_events` | Window-clamped; `limit≤50` |
| `lookup_sigma_rule` | Adds `rule-*` to ledger |
| `lookup_attack_technique` | Adds `attack-*` to ledger |
| `decode_powershell` | Pure; no LLM |

Every call returns `ToolResult(ok, data, evidence_ids, truncated, error)`. Args validated with Pydantic. Trace appends a `ToolCallRecord`. Errors are data: never exceptions into the agent loop.

### 5.5 Agent graph

- plan: hypotheses + first queries (ablation: skip planner).
- investigate: tool-calling loop; stop on no tool call or `max_tool_calls` (default 12). Budget exhaustion is recorded.
- write: structured `CaseFile`; prompt includes ledger digest; ids outside the digest do not exist.
- verify / repair: deterministic (§5.6); repair ≤2; else strip unsupported claims and degrade (`verification.status = "degraded"`). A fabricated claim never leaves the system clean.

`ChatModel` protocol, three implementations:

| Impl | Role |
|---|---|
| `OllamaChat` | Default product path: `qwen2.5:7b-instruct` (fits 8 GB VRAM) |
| `OpenAIChat` | Proprietary teacher / ablation (cost, latency, quality table) |
| `ScriptedChat` | Tests / CI: no network |

`qwen2.5:14b` may appear as an optional offline ablation with CPU/RAM offload; it is not the default and not required for v1.

Default budgets: `max_tool_calls=12`, `max_llm_calls=20`, `timeout_s=180`.

### 5.6 Verifier

Pure function over `(CaseFile, EvidenceLedger, CaseStore)`:

1. Every `Claim.evidence` non-empty; every id matches the grammar.
2. Every `ev-*` id is in the ledger (seen this run), not merely in the store.
3. Every `rule-*` / `attack-*` was looked up this run.
4. Every pid in `scope.involved_pids` has a cited `process_create`.
5. Technique ids exist in the knowledge base.
6. Enums valid; timeline sorted; `summary` ≤ 3 sentences.

Returns `VerificationReport{passed, errors: list[VerificationError{path, code, message}]}` with stable error codes (`UNKNOWN_EVIDENCE`, `EVIDENCE_NOT_IN_LEDGER`, `PID_UNSUPPORTED`, …).

## 6. Dataset

### 6.1 Size and sources (v1 cut: ~24 scenarios)

| Class | Count (approx.) | Origin |
|---|---|---|
| Malicious | ~12 | OTRF Security-Datasets `datasets/atomic/windows/` (download by URL + sha256; **do not vendor). Upstream license is MIT. |
| Benign twins | ~8 | Authored: same Sigma trigger in admin context (SCCM `-enc`, AV/backup LSASS read, RMM `schtasks`, etc.) |
| Not enough evidence | ~4 | Truncated windows → gold `not_enough_evidence` + collect_* actions |

Split: ~16 dev / ~8 test. Test touched only by `alert2attack eval run --split test`.

Phase 1 ships 3 authored scenarios (one per gold class) before the OTRF importer exists.

### 6.2 Gold

```yaml
gold:
  verdict: malicious | likely_benign | not_enough_evidence   # "suspicious" is never gold
  techniques: [T1059.001, ...]
  root_pid: 4120
  key_pids: [4120, 5288]
  persistence_evidence: [ev-0007]
  acceptable_actions: [isolate_host, kill_process, collect_script]
  unacceptable_actions: [close_as_benign]
  narrative: "one paragraph reference story for the judge"
```

Gold verdict rule: OTRF → `malicious`; authored twin → `likely_benign`; truncated → `not_enough_evidence`. Agent `suspicious` on a malicious gold costs 1 (not 5) in the severity matrix.

## 7. Evaluation

### 7.1 Primary metrics (deterministic)

| Metric | Definition |
|---|---|
| Verdict accuracy / macro-F1 | 4-class pred vs 3-class gold; `suspicious` adjacent to `malicious` |
| Severity-weighted cost | malicious→likely_benign=5, malicious→NEE=3, malicious→suspicious=1, likely_benign→malicious=2, other mismatch=1, match=0 |
| Technique P/R/F1 | Set overlap at technique level |
| Scope | Root-process hit; key-pid recall; persistence recall |
| Citation validity (pre-repair) | Fraction of claims whose every id is in the ledger before repair: ExCyTIn-style process metric |
| Citation validity (post-repair) | Same after verify/repair |
| Unsupported-claim rate | Claims stripped by the verifier per case |
| Action safety | Any `unacceptable_action`; ≥1 `acceptable_action` |
| Efficiency | Tool calls, LLM calls, wall time, tokens; budget-exhaustion rate |

Secondary (optional LLM-as-judge, local by default): timeline faithfulness to gold narrative; usefulness of `open_questions`. Never mixed into the primary table.

### 7.2 Arms (v1)

| Arm | Purpose |
|---|---|
| `b0` | Single prompt, window inlined: must be beaten on citation + scope |
| `agent-local-7b` | Headline product arm (Ollama 7B) |
| `agent-teacher` | Proprietary upper bound / cost, quality comparison |
| `agent-noverify` | Same agent without repair: exposes pre-repair citation numbers |

Cut from v1 (YAGNI): `agent-noplan`, budget sweeps, mandatory 14B arm.

Output: `reports/<date>-<arm>.json` + Markdown table in README. Record model tag, prompt hash, dataset hash. Prefer `temperature=0` / fixed seed where available.

Success bar: `agent-teacher` beats `b0` on citation validity and scope recall (proves the loop). `agent-local-7b` is reported honestly as the sovereign default, even if weaker, with latency/cost notes.

## 8. Serving and operations

- `POST /investigations` → `202`; `GET /investigations/{id}` → status, case file, verification, trace summary. Sync variant for demos. In-memory jobs (no queue).
- `GET /metrics` (Prometheus): investigations by verdict, verification failures by code, tool-call histogram, LLM latency, budget exhaustion.
- Structured JSON logs (`structlog`) with `investigation_id`.
- `docker compose up`: `api` + `ollama` (7B pulled on first start).
- CI (GitHub Actions): `uv sync`, `pytest`, `ruff`, `mypy --strict` on PR; no live LLM in CI (`ScriptedChat` only). Live tests: `@pytest.mark.live`, `ALERT2ATTACK_LIVE=1`.

## 9. Fine-tuning (explicitly out of scope)

Fine-tuning is secondary to the investigation loop and its evaluation, which come first.

If revisited later (not this project): distill teacher tool-call traces → LoRA SFT of `qwen2.5:7b` → re-run held-out eval → report delta. Until then: the architecture is distillation-ready (persisted traces), and the untuned local baseline is measured first.

## 10. Delivery plan

| Phase | Deliverable | What it gives |
|---|---|---|
| 1 | Domain, `CaseStore`, tools + ledger, knowledge, 3 scenarios, CLI | Boxed telemetry |
| 2 | OTRF importer, ~24 gold scenarios, split, ATT&CK subset, ~Sigma rules | Real investigation object |
| 3 | LangGraph agent, 7B default, teacher client, budgets, traces | Plan + tool calling + local-first |
| 4 | Verifier + repair + degrade | Faithfulness enforced |
| 5 | Eval harness, B0, arms, pre/post citation metrics, README table | Measured + model trade-offs |
| 6 | FastAPI, Prometheus, Compose, CI, run guide | Proto to prod shell |

Out of v1: LoRA, case UI, multi-host pivot, YARA/memory forensics, auth, server DB, threat-intel RAG, streaming UI.

Phase 1 has a full TDD plan (companion document). Phases 2 to 6 get plan documents when the prior phase is green; interfaces above are fixed so later plans do not reopen design.

## 11. Global constraints

- Python ≥ 3.12, `uv`, `src/` layout, package name `alert2attack`.
- Pydantic v2 at boundaries; `extra="forbid"`.
- SQLite via stdlib `sqlite3`; no ORM; no server database.
- No network in the default test suite.
- `ruff` (E, F, I, B, UP) and `mypy --strict` clean on `src/`.
- Evidence id grammar as in §5.2.
- Default model tag `qwen2.5:7b-instruct`; default budgets as in §5.5.
- Gold never enters `CaseStore`. Only `alert2attack.tools` reads `CaseStore` during a run.
- Tools: no shell; errors are data.

## 12. Risks and mitigations

| Risk | Mitigation |
|---|---|
| 7B tool-calling is flaky | Tiny tool surface; planner; strict schemas; ScriptedChat CI; teacher arm proves loop ceiling |
| 8 GB VRAM | 7B default; 14B only optional offload ablation |
| Small test set (~8) | Report counts; never tune on test; honesty in README |
| Authored twins too clean | Copy benign noise from OTRF; `datasets/AUTHORING.md` in Phase 2 |
| OTRF field drift | Manifest records dataset version + sha256; normalizer tests on fixtures |

## 13. Scope decisions (YAGNI)

Out of scope for v1: running detection rules online, multi-host pivoting, YARA/file analysis, memory forensics, full web console, authentication, database server, retrieval over threat-intel corpora, streaming UI, fine-tuning.
