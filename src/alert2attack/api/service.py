"""Run an investigation for the API (sync or background worker)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import structlog

from alert2attack.agent.budget import budget_from_env, max_investigate_turns_from_env
from alert2attack.agent.investigator import InvestigationResult, Investigator
from alert2attack.agent.progress import ProgressSink
from alert2attack.api.factory import ChatFactory, default_chat_factory
from alert2attack.api.metrics import observe_result, observe_verification_errors
from alert2attack.domain.scenario import SCENARIOS_ROOT, load_scenario
from alert2attack.tools.registry import ToolRegistry

log = structlog.get_logger("alert2attack.api")


def result_payload(result: InvestigationResult) -> dict[str, Any]:
    verification = result.verification
    return {
        "case_file": result.case_file.model_dump(mode="json"),
        "trace": {
            "model": result.trace.model,
            "budget": result.trace.budget,
            "llm_calls": [c.model_dump() for c in result.trace.llm_calls],
            "tool_calls": [
                {
                    "seq": c.seq,
                    "tool": c.tool,
                    "ok": c.ok,
                    "evidence_ids": c.evidence_ids,
                    "duration_ms": c.duration_ms,
                }
                for c in result.trace.tool_calls
            ],
            "notes": result.trace.notes,
        },
        "verification": None if verification is None else verification.model_dump(mode="json"),
    }


RETRIEVAL_TOOL_ENV = "ALERT2ATTACK_RETRIEVAL_TOOL"


def _registry_from_env() -> ToolRegistry | None:
    """``None`` means the default registry, which is what every measured run used.

    The search tool is added only when ``ALERT2ATTACK_RETRIEVAL_TOOL=1``. It is
    unmeasured at the agent level (see alert2attack.tools.retrieval_tools), so it must
    never appear by accident.
    """
    if os.environ.get(RETRIEVAL_TOOL_ENV) != "1":
        return None
    from alert2attack.retrieval.factory import shared_retriever
    from alert2attack.tools.retrieval_tools import retrieval_registry

    return retrieval_registry(shared_retriever())


def run_investigation(
    *,
    scenario_id: str,
    model: str = "ollama",
    root: Path = SCENARIOS_ROOT,
    chat_factory: ChatFactory | None = None,
    investigation_id: str | None = None,
    progress: ProgressSink | None = None,
) -> dict[str, Any]:
    structlog.contextvars.bind_contextvars(investigation_id=investigation_id or "sync", scenario_id=scenario_id)
    log.info("investigation.start", model=model)
    factory = chat_factory or default_chat_factory
    llm = factory(model)
    scenario = load_scenario(root / scenario_id)
    result = Investigator(
        llm=llm,
        registry=_registry_from_env(),
        budget=budget_from_env(),
        max_investigate_turns=max_investigate_turns_from_env(),
        progress=progress,
    ).run_scenario(scenario)
    payload = result_payload(result)
    llm_ms = sum(c.duration_ms for c in result.trace.llm_calls)
    status = result.verification.status if result.verification else "unknown"
    observe_result(
        verdict=result.case_file.verdict.value,
        status=status,
        model=result.trace.model,
        tool_calls=int(result.trace.budget.get("tool_calls", 0)),
        llm_ms=llm_ms,
        budget=result.trace.budget,
    )
    if result.verification and result.verification.errors:
        observe_verification_errors([e.code for e in result.verification.errors])
    log.info(
        "investigation.done",
        verdict=result.case_file.verdict.value,
        verification_status=status,
        tool_calls=result.trace.budget.get("tool_calls"),
    )
    return payload
