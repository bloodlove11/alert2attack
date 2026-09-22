"""B0 baseline: single prompt with inlined telemetry, no tools (design §7.2)."""

from __future__ import annotations

import json
from time import perf_counter

from alert2attack.agent.budget import Budget
from alert2attack.agent.investigator import InvestigationResult
from alert2attack.agent.jsonutil import extract_json_object
from alert2attack.agent.llm import ChatMessage, ChatModel
from alert2attack.agent.prompts import CASEFILE_JSON_SCHEMA_HINT, WRITE_SYSTEM
from alert2attack.agent.trace import Trace, llm_call_record
from alert2attack.domain.casefile import ActionRecommendation, CaseFile, Claim, NextAction, Verdict
from alert2attack.domain.scenario import Scenario
from alert2attack.domain.scope import hydrate_involved_pids, pids_from_events
from alert2attack.verify.models import VerificationReport

B0_MAX_EVENTS = 40


def _inline_window(scenario: Scenario, *, max_events: int = B0_MAX_EVENTS) -> str:
    events = scenario.events[:max_events]
    rows = [
        {
            "event_id": e.event_id,
            "kind": e.kind.value,
            "ts": e.ts.isoformat(),
            "pid": e.pid,
            "image": e.image,
            "command_line": (e.command_line or "")[:240],
        }
        for e in events
    ]
    alert = scenario.alert.model_dump(mode="json")
    return json.dumps({"alert": alert, "events": rows}, indent=2, default=str)


def _fallback_casefile() -> CaseFile:
    return CaseFile(
        verdict=Verdict.NOT_ENOUGH_EVIDENCE,
        confidence="low",
        summary="B0 baseline could not produce a valid case file.",
        next_actions=[
            ActionRecommendation(
                action=NextAction.ESCALATE,
                rationale=Claim(text="b0 parse failure", evidence=["ev-0001"]),
            )
        ],
        open_questions=["B0 parse failure"],
    )


def run_b0(scenario: Scenario, llm: ChatModel) -> InvestigationResult:
    """One LLM call; no tools → empty ledger → citation validity expected low unless careful."""
    budget = Budget(max_tool_calls=0, max_llm_calls=2)
    trace = Trace(case_id=scenario.scenario_id, model=llm.model_name)
    user = (
        "You are a B0 baseline: you see the alert and a truncated event dump inline. "
        "You cannot call tools. Apply the write-system verdict rubric and asymmetric safety "
        "rule to this dump. Never emit likely_benign or close_as_benign when the dump shows "
        "attack-chain indicators (audit policy tampering, credential dump, LOLBin/script "
        "execution, persistence); prefer malicious, or suspicious if partial. A false "
        "likely_benign is worse than not_enough_evidence. likely_benign is only for a benign "
        "FP (LSASS/handle access without dump or attack techniques). Do not default to "
        "not_enough_evidence or suspicious when the inline events already show a clear attack "
        "chain, and do not default to not_enough_evidence when the dump is a consistent benign "
        "false-positive pattern with no attack techniques.\n"
        "Only cite event ids that appear in the dump. If you set scope.root_process, "
        "scope.involved_pids MUST include that process's pid from the dump plus other cited "
        "dump pids. Never leave involved_pids empty if a root is claimed. Do not invent pids "
        "— only pids that appear on dump events.\n\n"
        f"{_inline_window(scenario)}\n\n"
        f"{CASEFILE_JSON_SCHEMA_HINT}\n"
        "Return CaseFile JSON only."
    )
    messages = [
        ChatMessage(role="system", content=WRITE_SYSTEM),
        ChatMessage(role="user", content=user),
    ]
    budget.consume_llm()
    started = perf_counter()
    resp = llm.complete(messages)
    trace.add_llm(
        llm_call_record(
            seq=1,
            role="write",
            model=llm.model_name,
            messages=messages,
            response=resp,
            duration_ms=(perf_counter() - started) * 1000.0,
        )
    )
    try:
        case_file = CaseFile.model_validate(extract_json_object(resp.content or ""))
    except Exception:  # noqa: BLE001
        case_file = _fallback_casefile()
    else:
        case_file = hydrate_involved_pids(
            case_file, pids_from_events(scenario.events[:B0_MAX_EVENTS])
        )
    trace.budget = budget.snapshot()
    verification = VerificationReport(
        passed=False,
        status="degraded",
        errors=[],
        pre_repair_errors=[],
        repairs_used=0,
        stripped_claims=0,
    )
    return InvestigationResult(case_file=case_file, trace=trace, verification=verification)
