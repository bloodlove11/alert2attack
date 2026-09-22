"""Where retrieval meets the agent and the API. The frozen path must not move."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from alert2attack.agent.budget import Budget
from alert2attack.agent.investigator import Investigator
from alert2attack.agent.llm import ChatResponse, ScriptedChat, ToolCallRequest
from alert2attack.api import service
from alert2attack.api.app import create_app
from alert2attack.api.auth import AuthConfig
from alert2attack.domain.scenario import Scenario
from alert2attack.retrieval.corpus import Corpus, Doc
from alert2attack.retrieval.retriever import Retriever
from alert2attack.tools import default_registry
from alert2attack.tools.retrieval_tools import TOOL_NAME, SearchArgs, retrieval_registry

# The tool list every measured run used. If this changes, the frozen OTRF numbers
# were measured against a different agent, and that has to be a decision.
FROZEN_TOOLS = [
    "decode_powershell",
    "get_alert",
    "get_events_for_process",
    "get_process",
    "get_process_tree",
    "lookup_attack_technique",
    "lookup_sigma_rule",
    "search_events",
]


def _retriever() -> Retriever:
    docs = [
        Doc(
            doc_id="attack-T1218.005",
            kind="attack_technique",
            title="System Binary Proxy Execution: Mshta",
            text="System Binary Proxy Execution: Mshta. mshta executes remote html application script",
        ),
        Doc(
            doc_id="attack-T1053.005",
            kind="attack_technique",
            title="Scheduled Task",
            text="Scheduled Task. scheduled task persistence at logon",
        ),
        Doc(
            doc_id="rule-win_susp_mshta",
            kind="sigma_rule",
            title="Suspicious Mshta",
            text="Suspicious Mshta. mshta launched",
        ),
    ]
    return Retriever(Corpus(docs=docs, source="test"))


# -- the frozen path ----------------------------------------------------------


def test_the_default_tool_list_is_unchanged() -> None:
    assert default_registry().names() == FROZEN_TOOLS


def test_the_search_tool_is_not_in_the_default_registry() -> None:
    assert TOOL_NAME not in default_registry().names()


def test_the_retrieval_registry_is_the_default_plus_exactly_one_tool() -> None:
    names = retrieval_registry(_retriever()).names()
    assert sorted(names) == sorted([*FROZEN_TOOLS, TOOL_NAME])


def test_the_service_uses_the_default_registry_unless_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(service.RETRIEVAL_TOOL_ENV, raising=False)
    assert service._registry_from_env() is None


@pytest.mark.parametrize("value", ["0", "", "true", "yes", "on"])
def test_only_the_literal_1_turns_the_search_tool_on(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    """A stray value must not quietly change what the model is shown."""
    monkeypatch.setenv(service.RETRIEVAL_TOOL_ENV, value)
    assert service._registry_from_env() is None


def test_the_flag_builds_a_registry_with_the_search_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    from alert2attack.retrieval import factory

    monkeypatch.setenv(service.RETRIEVAL_TOOL_ENV, "1")
    monkeypatch.setattr(factory, "shared_retriever", _retriever)
    registry = service._registry_from_env()
    assert registry is not None
    assert TOOL_NAME in registry.names()


# -- the tool -----------------------------------------------------------------


def test_the_tool_returns_candidates_and_no_evidence() -> None:
    """A hit is not evidence. Only lookup_attack_technique puts a technique in the
    ledger, which is what the verifier accepts."""
    registry = retrieval_registry(_retriever())
    from alert2attack.knowledge.base import KnowledgeBase
    from alert2attack.store.case_store import CaseStore
    from alert2attack.tools.context import EvidenceLedger, ToolContext

    ctx = ToolContext(store=CaseStore(), case_id="x", ledger=EvidenceLedger(), knowledge=KnowledgeBase.load_default())
    result = registry.call(ctx, TOOL_NAME, {"query": "mshta remote script", "k": 3})

    assert result.ok
    assert result.evidence_ids == []
    assert result.data["candidates"][0]["technique_id"] == "T1218.005"
    assert "lookup_attack_technique" in result.data["note"]
    assert not ctx.ledger.ids(), "searching must leave the ledger empty"


def test_the_tool_returns_techniques_only_never_rules() -> None:
    registry = retrieval_registry(_retriever())
    from alert2attack.knowledge.base import KnowledgeBase
    from alert2attack.store.case_store import CaseStore
    from alert2attack.tools.context import EvidenceLedger, ToolContext

    ctx = ToolContext(store=CaseStore(), case_id="x", ledger=EvidenceLedger(), knowledge=KnowledgeBase.load_default())
    result = registry.call(ctx, TOOL_NAME, {"query": "mshta launched", "k": 10})
    assert all(c["technique_id"].startswith("T") for c in result.data["candidates"])


@pytest.mark.parametrize(
    "bad",
    [{"query": "ab"}, {"query": "x" * 501}, {"query": "fine query", "k": 0}, {"query": "fine query", "k": 11}],
)
def test_the_tool_validates_its_arguments(bad: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        SearchArgs.model_validate(bad)


def test_the_tool_schema_reaches_the_model() -> None:
    schemas = retrieval_registry(_retriever()).openai_schemas()
    search = next(s for s in schemas if s["function"]["name"] == TOOL_NAME)
    assert "call lookup_attack_technique" in search["function"]["description"]


def _casefile_json(evidence: str) -> str:
    return json.dumps(
        {
            "verdict": "suspicious",
            "confidence": "low",
            "summary": "Encoded PowerShell ran from cmd.",
            "timeline": [{"ts": "2024-01-01T00:10:00Z", "text": "encoded ps", "evidence": [evidence]}],
            "techniques": [],
            "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
            "next_actions": [{"action": "escalate", "rationale": {"text": "review", "evidence": [evidence]}}],
            "open_questions": [],
        }
    )


def test_an_agent_can_call_search_and_the_ledger_stays_clean(downloader_scenario: Scenario) -> None:
    payload = _casefile_json("ev-0002")
    chat = ScriptedChat(
        [
            ChatResponse(content="plan: search then write"),
            ChatResponse(
                tool_calls=(ToolCallRequest(id="s1", name=TOOL_NAME, arguments={"query": "mshta remote script"}),)
            ),
            ChatResponse(content="ready to write"),
            ChatResponse(content=payload),
            ChatResponse(content=payload),
            ChatResponse(content=payload),
        ]
    )
    result = Investigator(
        llm=chat,
        registry=retrieval_registry(_retriever()),
        budget=Budget(max_tool_calls=8, max_llm_calls=10),
    ).run_scenario(downloader_scenario)

    searched = [c for c in result.trace.tool_calls if c.tool == TOOL_NAME]
    assert len(searched) == 1 and searched[0].ok
    assert not any(e.startswith("attack-") for c in result.trace.tool_calls for e in c.evidence_ids)


# -- the API ------------------------------------------------------------------


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(retriever=_retriever(), auth_config=AuthConfig(enabled=False)))


def test_search_returns_hits_with_the_corpus_identified(client: TestClient) -> None:
    body = client.get("/search/techniques", params={"q": "mshta remote script"}).json()
    assert body["hits"][0]["doc_id"] == "attack-T1218.005"
    assert body["corpus_source"] == "test"
    assert body["n_techniques"] == 2
    assert body["mode"] == "lexical"
    assert body["available_modes"] == ["lexical"]


def test_search_covers_techniques_only(client: TestClient) -> None:
    hits = client.get("/search/techniques", params={"q": "mshta"}).json()["hits"]
    assert hits and {h["kind"] for h in hits} == {"attack_technique"}


def test_a_mode_that_is_not_configured_is_409(client: TestClient) -> None:
    resp = client.get("/search/techniques", params={"q": "mshta", "mode": "dense"})
    assert resp.status_code == 409
    assert "lexical" in resp.json()["detail"]


def test_search_validates_its_input(client: TestClient) -> None:
    assert client.get("/search/techniques", params={"q": "x"}).status_code == 422
    assert client.get("/search/techniques", params={"q": "ok query", "k": 0}).status_code == 422
    assert client.get("/search/techniques", params={"q": "ok query", "k": 26}).status_code == 422
    assert client.get("/search/techniques", params={"q": "ok query", "mode": "nonsense"}).status_code == 422
    assert client.get("/search/techniques").status_code == 422


def test_search_requires_auth_when_auth_is_on() -> None:
    secured = TestClient(
        create_app(
            retriever=_retriever(),
            auth_config=AuthConfig(enabled=True, username="a", password_hash="scrypt$AA==$AA==", secret="s"),
        )
    )
    assert secured.get("/search/techniques", params={"q": "mshta"}).status_code == 401


def test_search_carries_no_gold(client: TestClient) -> None:
    body = client.get("/search/techniques", params={"q": "mshta"}).text
    for marker in ("GOLD-MARKER", "key_pids", "acceptable_actions", "narrative"):
        assert marker not in body


def test_the_route_is_in_the_schema_the_console_generates_from(client: TestClient) -> None:
    assert "/search/techniques" in client.get("/openapi.json").json()["paths"]
