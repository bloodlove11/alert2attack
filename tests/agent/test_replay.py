"""The replay responder: a demo device that must never reach evaluation."""

from __future__ import annotations

import json

import pytest

from alert2attack.agent.budget import Budget
from alert2attack.agent.investigator import Investigator
from alert2attack.agent.llm import ChatMessage
from alert2attack.agent.progress import RecordingSink, ToolCallEvent
from alert2attack.agent.replay import MODEL_NAME, ReplayChat, replay_delay_seconds
from alert2attack.domain.scenario import Scenario


def _msg(text: str) -> list[ChatMessage]:
    return [ChatMessage(role="user", content=text)]


def test_first_turn_is_a_plan() -> None:
    chat = ReplayChat(delay_s=0)
    resp = chat.complete(_msg("alert preview"))
    assert resp.content and "case file" in resp.content.lower()
    assert not resp.tool_calls


def test_second_turn_calls_a_real_tool_when_a_pid_is_visible() -> None:
    chat = ReplayChat(delay_s=0)
    chat.complete(_msg("plan"))
    resp = chat.complete(_msg('{"pid": 4242, "image": "cmd.exe"}'))
    assert resp.tool_calls
    call = resp.tool_calls[0]
    assert call.name == "get_process_tree"
    assert call.arguments == {"pid": 4242}


def test_third_turn_searches_so_the_ledger_is_not_one_event() -> None:
    chat = ReplayChat(delay_s=0)
    chat.complete(_msg("plan"))
    chat.complete(_msg('{"pid": 10}'))
    resp = chat.complete(_msg("tool result"))
    assert resp.tool_calls
    assert resp.tool_calls[0].name == "search_events"


def test_second_turn_degrades_gracefully_without_a_pid() -> None:
    chat = ReplayChat(delay_s=0)
    chat.complete(_msg("plan"))
    resp = chat.complete(_msg("no pid anywhere"))
    assert not resp.tool_calls
    assert resp.content


def test_write_turn_only_cites_evidence_it_was_shown() -> None:
    """The same reason a real run passes verification: no invented ids."""
    chat = ReplayChat(delay_s=0)
    for _ in range(4):
        chat.complete(_msg("setup"))
    resp = chat.complete(_msg("ledger: ev-0007 ev-0009 and some prose"))

    assert resp.content is not None
    case_file = json.loads(resp.content)
    cited = {e for entry in case_file["timeline"] for e in entry["evidence"]}
    assert cited <= {"ev-0007", "ev-0009"}


def test_write_turn_abstains_when_the_prompt_has_no_evidence() -> None:
    chat = ReplayChat(delay_s=0)
    for _ in range(4):
        chat.complete(_msg("setup"))
    resp = chat.complete(_msg("nothing useful here"))

    assert resp.content is not None
    assert json.loads(resp.content)["verdict"] == "not_enough_evidence"


def test_delay_is_configurable_and_defaults_sanely(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALERT2ATTACK_REPLAY_DELAY_MS", "0")
    assert replay_delay_seconds() == 0.0
    monkeypatch.setenv("ALERT2ATTACK_REPLAY_DELAY_MS", "250")
    assert replay_delay_seconds() == 0.25
    monkeypatch.setenv("ALERT2ATTACK_REPLAY_DELAY_MS", "not-a-number")
    assert replay_delay_seconds() > 0, "a bad value must not make the demo hang or crash"


# -- it drives the real pipeline ----------------------------------------------


def test_a_replay_run_drives_the_real_pipeline(downloader_scenario: Scenario) -> None:
    """Only the model is fake: graph, tools, ledger and verifier are real."""
    sink = RecordingSink()
    result = Investigator(
        llm=ReplayChat(delay_s=0),
        budget=Budget(max_tool_calls=8, max_llm_calls=10),
        progress=sink,
    ).run_scenario(downloader_scenario)

    assert result.verification is not None
    assert result.verification.passed, "nothing unsupported may ship"
    assert result.trace.model == MODEL_NAME

    tool_events = [e for e in sink.events if isinstance(e, ToolCallEvent)]
    assert tool_events, "a replay run still exercises real tools"
    assert any(e.type == "lever" for e in sink.events)


def test_replay_can_end_degraded_and_that_is_the_verifier_working(
    downloader_scenario: Scenario,
) -> None:
    """Documents a real interaction, not a replay defect.

    The graph hydrates ``scope.involved_pids`` from the store after the write.
    It can add a pid that was only ever seen as a ppid or in a non-process
    event, and verification then rejects it because no ``process_create`` for
    that pid is in the ledger. The claim is stripped and the case ships
    degraded — which is the verifier doing its job, and is exactly what the
    console's degraded banner is for.

    A real model on this scenario hits the same path; nothing here is specific
    to the replay responder.
    """
    result = Investigator(
        llm=ReplayChat(delay_s=0),
        budget=Budget(max_tool_calls=8, max_llm_calls=10),
    ).run_scenario(downloader_scenario)

    assert result.verification is not None
    assert result.verification.status in {"passed", "repaired", "degraded"}
    if result.verification.status == "degraded":
        assert result.verification.stripped_claims > 0
        assert not result.verification.errors, "stripping must leave nothing unsupported"


def test_replay_citations_are_all_in_the_ledger(downloader_scenario: Scenario) -> None:
    result = Investigator(
        llm=ReplayChat(delay_s=0),
        budget=Budget(max_tool_calls=8, max_llm_calls=10),
    ).run_scenario(downloader_scenario)

    ledger = {eid for call in result.trace.tool_calls if call.ok for eid in call.evidence_ids}
    cited = {e for entry in result.case_file.timeline for e in entry.evidence}
    assert cited <= ledger


# -- the boundary against evaluation ------------------------------------------


def test_eval_arms_cannot_resolve_to_the_replay_model() -> None:
    """A number produced by a canned responder would be meaningless."""
    from alert2attack.eval import runner

    source = runner.build_arm_llm.__code__.co_consts
    assert not any(isinstance(c, str) and "replay" in c for c in source if c is not None)


def test_replay_is_not_reachable_from_build_chat_model() -> None:
    """The CLI's model builder is shared with eval paths; keep replay out of it."""
    from alert2attack.agent.investigator import build_chat_model

    with pytest.raises(ValueError, match="unknown chat model"):
        build_chat_model("replay")
