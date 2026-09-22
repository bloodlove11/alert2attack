"""LangGraph investigation graph: plan → investigate (ReAct tool loop) → write.

Architectural rules (design §5.5):
- plan proposes hypotheses (optional ablation: skip_plan).
- investigate is a *continuing* tool-calling conversation: assistant tool_calls +
  role=tool results stay in the message thread (required for 7B tool use).
- stop on no tool calls, optional tool/LLM/time caps (default unbounded), or a turn cap (0 = none).
- write sees only the ledger digest + compact tool summaries — never invents ids.
- Side-effect handles (store/ledger/budget) live on the runner; graph state is the
  serializable conversation + outputs.
"""

from __future__ import annotations

import json
from time import perf_counter
from typing import Any, Literal, TypedDict, cast

from langgraph.graph import END, START, StateGraph

from alert2attack.agent.budget import Budget
from alert2attack.agent.jsonutil import parse_case_file
from alert2attack.agent.llm import ChatMessage, ChatModel, ChatResponse, ToolCallRequest
from alert2attack.agent.lsass_fp import apply_lsass_fp_ceiling
from alert2attack.agent.progress import ProgressEmitter
from alert2attack.agent.prompts import (
    CASEFILE_JSON_SCHEMA_HINT,
    INVESTIGATE_SYSTEM,
    PLAN_SYSTEM,
    REPAIR_SYSTEM,
    WRITE_SYSTEM,
    investigate_user,
    plan_user,
    repair_user,
    write_user,
)
from alert2attack.agent.scope import known_pids_from_store
from alert2attack.agent.technique_candidates import technique_candidates_from_ledger
from alert2attack.agent.thin_window import apply_thin_window_ceiling
from alert2attack.agent.trace import Trace, llm_call_record
from alert2attack.agent.verdict_floor import apply_verdict_floor
from alert2attack.domain.casefile import ActionRecommendation, CaseFile, Claim, NextAction, Scope, Verdict
from alert2attack.domain.events import Event
from alert2attack.domain.scope import hydrate_involved_pids
from alert2attack.tools.context import ToolContext, ToolResult
from alert2attack.tools.registry import ToolRegistry
from alert2attack.verify import VerificationReport, degrade_casefile, verify
from alert2attack.verify.models import VerificationError, VerificationStatus

# Keep each investigate model turn small for 7B reliability.
_MAX_TOOL_CALLS_PER_TURN = 3
# 0 = no turn cap, matching Investigator. Budgets and the recursion limit stop the loop.
_DEFAULT_MAX_INVESTIGATE_TURNS = 0
_MAX_REPAIRS = 2
_TOOL_RESULT_CHARS = 1800
_DIGEST_PARTS_FOR_WRITE = 12


class GraphState(TypedDict, total=False):
    plan: str
    investigate_messages: list[ChatMessage]
    last_tool_summary: str
    tool_digest_parts: list[str]
    case_file: CaseFile | None
    pre_repair_case_file: CaseFile | None
    done_investigating: bool
    investigate_turns: int
    alert_preview: dict[str, Any]
    verification: VerificationReport | None
    repairs_used: int
    pre_repair_errors: list[dict[str, str]]
    verify_done: bool


def _summarize_tool(name: str, result: ToolResult, *, limit: int = _TOOL_RESULT_CHARS) -> str:
    if not result.ok:
        return f"{name}: ERROR {result.error}"
    payload = json.dumps(result.data, default=str)
    if len(payload) > limit:
        payload = payload[:limit] + "…(truncated)"
    return f"{name}: ok evidence={result.evidence_ids} truncated={result.truncated}\n{payload}"


def _degraded_casefile(reason: str, ledger_ids: list[str]) -> CaseFile:
    # An empty ledger means no action: every Claim has to cite something, and a
    # placeholder id would be exactly the fabricated citation this repo exists to
    # prevent. The reason still reaches the reader through open_questions.
    actions = (
        [
            ActionRecommendation(
                action=NextAction.ESCALATE,
                rationale=Claim(text=reason, evidence=[ledger_ids[0]]),
            )
        ]
        if ledger_ids
        else []
    )
    return CaseFile(
        verdict=Verdict.NOT_ENOUGH_EVIDENCE,
        confidence="low",
        summary="Investigation could not produce a reliable case file from available tool results.",
        timeline=[],
        techniques=[],
        scope=Scope(),
        next_actions=actions,
        open_questions=[reason, "Re-run with a stronger model or collect more telemetry."],
    )


def _tool_fingerprint(tc: ToolCallRequest) -> tuple[str, str]:
    return tc.name, json.dumps(tc.arguments, sort_keys=True, default=str)


class InvestigationGraph:
    def __init__(
        self,
        *,
        llm: ChatModel,
        registry: ToolRegistry,
        ctx: ToolContext,
        budget: Budget,
        trace: Trace,
        skip_plan: bool = False,
        max_investigate_turns: int = _DEFAULT_MAX_INVESTIGATE_TURNS,
        max_tools_per_turn: int = _MAX_TOOL_CALLS_PER_TURN,
        max_repairs: int = _MAX_REPAIRS,
        progress: ProgressEmitter | None = None,
    ) -> None:
        self.llm = llm
        self.registry = registry
        self.ctx = ctx
        self.budget = budget
        self.trace = trace
        # Defaults to a NullSink emitter: no caller outside the API observes this.
        self.progress = progress or ProgressEmitter()
        self.skip_plan = skip_plan
        self.max_investigate_turns = max_investigate_turns
        self.max_tools_per_turn = max_tools_per_turn
        self.max_repairs = max_repairs
        self._tools = registry.openai_schemas()
        self._recent_tool_fps: list[tuple[str, str]] = []

    def _llm(
        self,
        role: str,
        messages: list[ChatMessage],
        *,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
    ) -> ChatResponse:
        if not self.budget.consume_llm():
            self.trace.add_note(f"{role}: llm budget exhausted")
            return ChatResponse(content="BUDGET_EXHAUSTED")
        started = perf_counter()
        resp = self.llm.complete(messages, tools=tools, tool_choice=tool_choice)
        record = llm_call_record(
            seq=len(self.trace.llm_calls) + 1,
            role=role,
            model=self.llm.model_name,
            messages=messages,
            response=resp,
            duration_ms=(perf_counter() - started) * 1000.0,
        )
        self.trace.add_llm(record)
        self.progress.llm_call(record)
        return resp

    def _call_tool(self, name: str, arguments: dict[str, Any]) -> ToolResult | None:
        if not self.budget.consume_tool():
            self.trace.add_note(f"tool budget exhausted before {name}")
            return None
        result = self.registry.call(self.ctx, name, arguments)
        # registry.call just appended this run's record to the ledger; emitting
        # from there keeps the stream and the trace built from one source.
        if self.ctx.ledger.calls:
            self.progress.tool_call(self.ctx.ledger.calls[-1])
        return result

    def bootstrap_alert(self) -> tuple[dict[str, Any], str]:
        """Always start from get_alert so the ledger has the trigger evidence id."""
        result = self._call_tool("get_alert", {})
        if result is None:
            return {"error": "tool budget exhausted before get_alert"}, "get_alert: skipped (budget)"
        preview = result.data if result.ok and isinstance(result.data, dict) else {"error": result.error}
        return preview, _summarize_tool("get_alert", result)

    def plan_node(self, state: GraphState) -> GraphState:
        self.progress.phase("plan")
        preview, digest = self.bootstrap_alert()
        if self.skip_plan:
            plan = (
                "1. Review the alert trigger and rule\n"
                "2. Expand the process tree for the trigger pid\n"
                "3. Search related events; look up Sigma/ATT&CK as needed\n"
                "4. Write the case file when evidence is sufficient"
            )
            self.trace.add_note("plan: skipped (skip_plan=True)")
        else:
            messages = [
                ChatMessage(role="system", content=PLAN_SYSTEM),
                ChatMessage(role="user", content=plan_user(preview)),
            ]
            resp = self._llm("plan", messages)
            plan = (resp.content or "").strip() or (
                "1. Review alert\n2. Inspect process tree\n3. Search related events"
            )
        return {
            "plan": plan,
            "alert_preview": preview,
            "last_tool_summary": digest,
            "tool_digest_parts": [digest],
            "investigate_messages": [],
            "investigate_turns": 0,
            "done_investigating": False,
            "case_file": None,
        }

    def _seed_investigate_messages(self, state: GraphState) -> list[ChatMessage]:
        existing = list(state.get("investigate_messages") or [])
        if existing:
            return existing
        return [
            ChatMessage(role="system", content=INVESTIGATE_SYSTEM),
            ChatMessage(
                role="user",
                content=investigate_user(
                    plan=state.get("plan", ""),
                    ledger_digest=sorted(self.ctx.ledger.ids()),
                    last_tool_summary=state.get("last_tool_summary", ""),
                    remaining_tools=self.budget.remaining_tools(),
                ),
            ),
        ]

    def _should_stop_investigate(self, state: GraphState) -> bool:
        remaining_tools = self.budget.remaining_tools()
        if remaining_tools is not None and remaining_tools <= 0:
            self.budget.tool_exhausted = True
            return True
        if self.budget.check_timeout():
            return True
        if self.budget.should_reserve_for_write():
            return True
        remaining_llm = self.budget.remaining_llm()
        if remaining_llm is not None and remaining_llm <= 0:
            self.budget.llm_exhausted = True
            return True
        turns = int(state.get("investigate_turns") or 0)
        return self.max_investigate_turns > 0 and turns >= self.max_investigate_turns

    def investigate_node(self, state: GraphState) -> GraphState:
        self.progress.phase("investigate")
        if self._should_stop_investigate(state):
            if self.budget.should_reserve_for_write() and not self.budget.timed_out:
                self.trace.add_note("investigate: stop (reserve write budget/time)")
            else:
                self.trace.add_note("investigate: stop (budget/timeout/max turns)")
            return {"done_investigating": True}

        messages = self._seed_investigate_messages(state)
        resp = self._llm("investigate", messages, tools=self._tools, tool_choice="auto")

        turns = int(state.get("investigate_turns") or 0) + 1
        if resp.content == "BUDGET_EXHAUSTED" or not resp.tool_calls:
            return {
                "done_investigating": True,
                "investigate_messages": messages
                + [ChatMessage(role="assistant", content=resp.content or "ready to write")],
                "investigate_turns": turns,
            }

        # Deduplicate identical tool calls within the turn; cap fan-out for 7B.
        selected: list[ToolCallRequest] = []
        seen_this_turn: set[tuple[str, str]] = set()
        for tc in resp.tool_calls:
            fp = _tool_fingerprint(tc)
            if fp in seen_this_turn or fp in self._recent_tool_fps[-6:]:
                self.trace.add_note(f"investigate: skip duplicate tool {tc.name}")
                continue
            seen_this_turn.add(fp)
            selected.append(tc)
            if len(selected) >= self.max_tools_per_turn:
                break

        if not selected:
            # Model only repeated prior calls — stop rather than spin.
            self.trace.add_note("investigate: only duplicate tool calls; ending loop")
            return {
                "done_investigating": True,
                "investigate_messages": messages
                + [ChatMessage(role="assistant", content=resp.content, tool_calls=resp.tool_calls)],
                "investigate_turns": turns,
            }

        assistant = ChatMessage(role="assistant", content=resp.content, tool_calls=tuple(selected))
        new_messages = messages + [assistant]
        parts = list(state.get("tool_digest_parts", []))
        last = state.get("last_tool_summary", "")
        executed = 0

        for tc in selected:
            result = self._call_tool(tc.name, tc.arguments)
            if result is None:
                break
            summary = _summarize_tool(tc.name, result)
            parts.append(summary)
            last = summary
            executed += 1
            self._recent_tool_fps.append(_tool_fingerprint(tc))
            new_messages.append(
                ChatMessage(
                    role="tool",
                    content=summary,
                    tool_call_id=tc.id,
                    name=tc.name,
                )
            )

        done = executed == 0 or self._should_stop_investigate({**state, "investigate_turns": turns})
        if done and self.budget.should_reserve_for_write() and not self.budget.timed_out:
            self.trace.add_note("investigate: stop (reserve write budget/time)")
        return {
            "done_investigating": done,
            "last_tool_summary": last,
            "tool_digest_parts": parts,
            "investigate_messages": new_messages,
            "investigate_turns": turns,
        }

    def _hydrate_involved_pids(self, case_file: CaseFile) -> CaseFile:
        known = known_pids_from_store(self.ctx.store, self.ctx.case_id, self.ctx.ledger.ids())
        return hydrate_involved_pids(case_file, known)

    def _boxed_events(self) -> list[Event]:
        return self.ctx.store.query_events(self.ctx.case_id, limit=1000)

    def _lever(self, lever_id: str, before: CaseFile, after: CaseFile) -> CaseFile:
        """Record one deterministic post-write control, fired or not.

        The trace only ever noted a lever that changed the verdict. The stream
        reports both outcomes, because "the LSASS ceiling looked at this and
        declined" is exactly what a reader wants to see on a benign case.
        """
        fired = after.verdict is not before.verdict
        if fired:
            self.trace.add_note(f"{lever_id}: {before.verdict.value} → {after.verdict.value}")
        self.progress.lever(
            lever_id,
            fired=fired,
            effect=f"{before.verdict.value} → {after.verdict.value}" if fired else None,
        )
        return after

    def _apply_levers(self, case_file: CaseFile) -> CaseFile:
        """Levers 1, 5 and 6: verdict floor, thin-window abstain, LSASS FP ceiling."""
        self.progress.phase("levers")
        events = self._boxed_events()
        floored = self._lever(
            "verdict_floor", case_file, apply_verdict_floor(case_file, self.ctx.knowledge)
        )
        capped = self._lever(
            "thin_window", floored, apply_thin_window_ceiling(floored, events)
        )
        return self._lever(
            "lsass_fp",
            capped,
            apply_lsass_fp_ceiling(
                capped,
                events,
                self.ctx.store.get_alert(self.ctx.case_id),
            ),
        )

    def write_node(self, state: GraphState) -> GraphState:
        self.progress.phase("write")
        ledger = sorted(self.ctx.ledger.ids())
        attack_candidates = technique_candidates_from_ledger(ledger, self.ctx.knowledge)
        digest = "\n\n".join(state.get("tool_digest_parts", [])[-_DIGEST_PARTS_FOR_WRITE:])
        messages = [
            ChatMessage(role="system", content=WRITE_SYSTEM + "\n\n" + CASEFILE_JSON_SCHEMA_HINT),
            ChatMessage(
                role="user",
                content=write_user(
                    plan=state.get("plan", ""),
                    ledger_digest=ledger,
                    tool_digest=digest,
                    attack_technique_candidates=attack_candidates,
                ),
            ),
        ]
        resp = self._llm("write", messages)
        attempt_raw = resp.content or ""
        parsed_ok = False
        case_file: CaseFile | None = None
        first_exc: Exception | None = None
        for attempt in range(2):
            if attempt_raw.strip() in {"", "BUDGET_EXHAUSTED"}:
                if attempt == 0:
                    self.trace.add_note("write: skipped parse (budget exhausted or empty)")
                    case_file = _degraded_casefile("CaseFile write budget exhausted or empty", ledger)
                else:
                    self.trace.add_note(f"write: parse failed once then budget exhausted: {first_exc!r}")
                    case_file = _degraded_casefile(f"CaseFile parse failed: {first_exc}", ledger)
                break
            try:
                case_file = parse_case_file(attempt_raw)
                parsed_ok = True
                break
            except Exception as exc:  # noqa: BLE001
                if attempt == 0:
                    first_exc = exc
                    retry_messages = messages + [
                        ChatMessage(role="assistant", content=attempt_raw),
                        ChatMessage(
                            role="user",
                            content=(
                                f"Previous output failed validation ({exc}). "
                                "Return ONLY valid CaseFile JSON using ledger ids exclusively."
                            ),
                        ),
                    ]
                    resp2 = self._llm("write", retry_messages)
                    attempt_raw = resp2.content or ""
                    continue
                self.trace.add_note(f"write: parse failed twice: {exc!r}")
                case_file = _degraded_casefile(f"CaseFile parse failed: {exc}", ledger)
        if parsed_ok and case_file is not None:
            case_file = self._hydrate_involved_pids(case_file)

        return {
            "case_file": case_file,
            "pre_repair_case_file": case_file,
            "done_investigating": True,
            "repairs_used": 0,
            "verify_done": False,
            "verification": None,
            "pre_repair_errors": [],
        }

    def verify_node(self, state: GraphState) -> GraphState:
        self.progress.phase("verify")
        case_file = state.get("case_file")
        if case_file is None:
            self.trace.add_note("verify: missing case_file")
            empty = _degraded_casefile("missing case_file", sorted(self.ctx.ledger.ids()))
            report = verify(empty, self.ctx.ledger, self.ctx.store, self.ctx.case_id, self.ctx.knowledge)
            return {"case_file": empty, "verification": report, "verify_done": True}

        report = verify(case_file, self.ctx.ledger, self.ctx.store, self.ctx.case_id, self.ctx.knowledge)
        repairs_used = int(state.get("repairs_used") or 0)
        pre_errors = list(state.get("pre_repair_errors") or [])
        if not pre_errors and report.errors:
            pre_errors = [e.model_dump() for e in report.errors]

        if report.passed:
            status: VerificationStatus = "passed" if repairs_used == 0 else "repaired"
            prior = [VerificationError.model_validate(e) for e in pre_errors]
            return {
                "case_file": self._apply_levers(case_file),
                "verification": VerificationReport(
                    passed=True,
                    status=status,
                    errors=[],
                    pre_repair_errors=prior,
                    repairs_used=repairs_used,
                    stripped_claims=0,
                ),
                "verify_done": True,
                "pre_repair_errors": pre_errors,
            }

        if repairs_used < self.max_repairs:
            return {
                "verification": report,
                "verify_done": False,
                "pre_repair_errors": pre_errors,
            }

        # Out of repairs → deterministic degrade
        prior = [VerificationError.model_validate(e) for e in pre_errors]
        cleaned, final = degrade_casefile(
            case_file,
            self.ctx.ledger,
            store=self.ctx.store,
            case_id=self.ctx.case_id,
            knowledge=self.ctx.knowledge,
            prior_errors=prior,
            repairs_used=repairs_used,
        )
        self.trace.add_note(f"verify: degraded after {repairs_used} repair(s); stripped={final.stripped_claims}")
        # Restore grounded pids after strip so key_pid_recall sees trigger/ledger pids
        # (verifier/degrade formulas unchanged; they already ran on the hydrated file).
        cleaned = self._hydrate_involved_pids(cleaned)
        cleaned = self._apply_levers(cleaned)
        return {"case_file": cleaned, "verification": final, "verify_done": True, "pre_repair_errors": pre_errors}

    def repair_node(self, state: GraphState) -> GraphState:
        self.progress.phase("repair")
        case_file = state.get("case_file")
        report = state.get("verification")
        if case_file is None or report is None:
            return {"verify_done": True}

        ledger = sorted(self.ctx.ledger.ids())
        errors = [e.model_dump() for e in report.errors]
        messages = [
            ChatMessage(role="system", content=REPAIR_SYSTEM + "\n\n" + CASEFILE_JSON_SCHEMA_HINT),
            ChatMessage(
                role="user",
                content=repair_user(
                    case_file_json=case_file.model_dump_json(),
                    errors=errors,
                    ledger_digest=ledger,
                ),
            ),
        ]
        resp = self._llm("repair", messages)
        repairs_used = int(state.get("repairs_used") or 0) + 1
        try:
            repaired = parse_case_file(resp.content or "")
        except Exception as exc:  # noqa: BLE001
            self.trace.add_note(f"repair: parse failed ({exc!r}); keeping prior case file")
            repaired = case_file
        repaired = self._hydrate_involved_pids(repaired)
        return {
            "case_file": repaired,
            "repairs_used": repairs_used,
            "verify_done": False,
        }

    def build(self) -> Any:
        graph = StateGraph(GraphState)
        graph.add_node("plan", self.plan_node)
        graph.add_node("investigate", self.investigate_node)
        graph.add_node("write", self.write_node)
        graph.add_node("verify", self.verify_node)
        graph.add_node("repair", self.repair_node)
        graph.add_edge(START, "plan")
        graph.add_edge("plan", "investigate")

        def _route_investigate(state: GraphState) -> Literal["investigate", "write"]:
            if state.get("done_investigating"):
                return "write"
            return "investigate"

        def _route_verify(state: GraphState) -> Literal["repair", "__end__"]:
            if state.get("verify_done"):
                return "__end__"
            return "repair"

        graph.add_conditional_edges(
            "investigate", _route_investigate, {"investigate": "investigate", "write": "write"}
        )
        graph.add_edge("write", "verify")
        graph.add_conditional_edges("verify", _route_verify, {"repair": "repair", "__end__": END})
        graph.add_edge("repair", "verify")
        return graph.compile()


def run_graph(graph: Any, *, recursion_limit: int = 40) -> GraphState:
    """Invoke with an explicit recursion ceiling (plan + investigate + write + repair)."""
    final = graph.invoke({}, config={"recursion_limit": recursion_limit})
    return cast(GraphState, final)
