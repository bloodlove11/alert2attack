"""Shared API test fixtures: an offline agent run with no live LLM."""

from __future__ import annotations

import json

import pytest

from alert2attack.agent.llm import ChatResponse, ScriptedChat
from alert2attack.api.factory import ChatFactory
from alert2attack.domain.scenario import SCENARIOS_ROOT, load_scenario

# A committed OTRF scenario. Its manifest carries gold, which the boundary
# tests rely on.
SCENARIO = "otrf_empire_launcher_vbs"


@pytest.fixture
def scenario_id() -> str:
    return SCENARIO


@pytest.fixture
def scripted_factory() -> ChatFactory:
    """A chat factory that plays a fixed script: plan, ready, then a case file.

    The case file cites the alert's trigger event, which the graph always
    fetches first, so every citation resolves.
    """

    def factory(_model: str) -> ScriptedChat:
        scenario = load_scenario(SCENARIOS_ROOT / SCENARIO)
        eid = scenario.alert.trigger_event_id
        case_file = {
            "verdict": "malicious",
            "confidence": "medium",
            "summary": "OTRF empire launcher activity looks malicious.",
            "timeline": [
                {"ts": "2020-09-04T20:09:55Z", "text": "encoded powershell", "evidence": [eid]}
            ],
            "techniques": [],
            "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
            "next_actions": [
                {"action": "escalate", "rationale": {"text": "need analyst", "evidence": [eid]}},
            ],
            "open_questions": [],
        }
        payload = json.dumps(case_file)
        return ScriptedChat(
            [
                ChatResponse(content="1. alert 2. write"),
                ChatResponse(content="ready"),
                ChatResponse(content=payload),
                ChatResponse(content=payload),
                ChatResponse(content=payload),
            ]
        )

    return factory
