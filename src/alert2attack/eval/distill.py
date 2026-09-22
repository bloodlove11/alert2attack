"""Export investigation traces for LoRA / SFT distillation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from alert2attack.agent.investigator import InvestigationResult
from alert2attack.agent.llm import ChatMessage, ScriptedChat, to_openai_messages
from alert2attack.agent.trace import Trace
from alert2attack.domain.scenario import Scenario


def messages_to_openai(messages: list[ChatMessage]) -> list[dict[str, Any]]:
    return to_openai_messages(messages)


def turns_from_trace(trace: Trace) -> list[list[dict[str, Any]]]:
    """One OpenAI-style thread per LLM call: prompt messages plus the assistant reply."""
    out: list[list[dict[str, Any]]] = []
    for call in trace.llm_calls:
        if not call.messages:
            continue
        thread = [dict(m) for m in call.messages]
        if call.response:
            thread.append(dict(call.response))
        out.append(thread)
    return out


def distill_record(
    scenario: Scenario,
    result: InvestigationResult,
    *,
    prompt_messages: list[list[ChatMessage]] | None = None,
) -> dict[str, Any]:
    """One JSONL row for SFT. Prefer recorded live/teacher turns on the trace."""
    verification = result.verification
    messages = turns_from_trace(result.trace)
    if not messages and prompt_messages:
        messages = [messages_to_openai(turn) for turn in prompt_messages]
    return {
        "scenario_id": scenario.scenario_id,
        "split": scenario.split,
        "model": result.trace.model,
        "verification_status": verification.status if verification else None,
        "case_file": result.case_file.model_dump(mode="json"),
        "trace": {
            "llm_calls": [c.model_dump() for c in result.trace.llm_calls],
            "tool_calls": [c.model_dump() for c in result.trace.tool_calls],
            "budget": result.trace.budget,
            "notes": result.trace.notes,
        },
        "messages": messages,
        "gold_verdict": scenario.gold.verdict if scenario.gold else None,
    }


def append_distill_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")


def scripted_prompt_messages(llm: object) -> list[list[ChatMessage]] | None:
    if isinstance(llm, ScriptedChat):
        return list(llm.calls)
    return None
