"""Progress emission: the live side channel must describe the same run as the trace."""

from __future__ import annotations

import json

import pytest

from alert2attack.agent.budget import Budget
from alert2attack.agent.investigator import Investigator
from alert2attack.agent.llm import ChatResponse, ScriptedChat, ToolCallRequest
from alert2attack.agent.progress import (
    LedgerEvent,
    LeverEvent,
    LlmCallEvent,
    NullSink,
    ProgressEmitter,
    RecordingSink,
    ToolCallEvent,
    VerifyEvent,
    evidence_kind,
)
from alert2attack.domain.scenario import Scenario


def _write_json(evidence: str = "ev-0002") -> str:
    return json.dumps(
        {
            "verdict": "suspicious",
            "confidence": "low",
            "summary": "Encoded PowerShell ran from cmd.",
            "timeline": [{"ts": "2024-01-01T00:10:00Z", "text": "encoded ps", "evidence": [evidence]}],
            "techniques": [],
            "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
            "next_actions": [
                {"action": "escalate", "rationale": {"text": "review", "evidence": [evidence]}}
            ],
            "open_questions": [],
        }
    )


def _chat_with_a_tool_call() -> ScriptedChat:
    payload = _write_json()
    return ScriptedChat(
        [
            ChatResponse(content="plan: read the tree then write"),
            ChatResponse(
                tool_calls=(
                    ToolCallRequest(id="t1", name="get_process_tree", arguments={"pid": 10}),
                )
            ),
            ChatResponse(content="ready to write"),
            ChatResponse(content=payload),
            ChatResponse(content=payload),
            ChatResponse(content=payload),
        ]
    )


@pytest.fixture
def run(downloader_scenario: Scenario) -> RecordingSink:
    sink = RecordingSink()
    Investigator(
        llm=_chat_with_a_tool_call(),
        budget=Budget(max_tool_calls=8, max_llm_calls=10),
        progress=sink,
    ).run_scenario(downloader_scenario)
    return sink


# -- the emitter --------------------------------------------------------------


def test_null_sink_is_the_default() -> None:
    """The CLI and eval runner must not pay for, or depend on, progress."""
    emitter = ProgressEmitter()
    emitter.phase("plan")  # must not raise, must go nowhere
    assert isinstance(emitter._sink, NullSink)


def test_sequence_numbers_are_monotonic_across_event_types(run: RecordingSink) -> None:
    """A reconnecting client resumes by seq, so ordering must span every type."""
    seqs = [e.seq for e in run.events]
    assert seqs == list(range(1, len(seqs) + 1))


def test_elapsed_is_non_decreasing(run: RecordingSink) -> None:
    elapsed = [e.elapsed_ms for e in run.events]
    assert elapsed == sorted(elapsed)


@pytest.mark.parametrize(
    ("evidence_id", "expected"),
    [
        ("ev-0001", "event"),
        ("rule-win_powershell_encoded_command", "sigma_rule"),
        ("attack-T1059.001", "attack_technique"),
    ],
)
def test_evidence_kind_follows_the_id_grammar(evidence_id: str, expected: str) -> None:
    assert evidence_kind(evidence_id) == expected


# -- what a run emits ---------------------------------------------------------


def test_phases_are_reported_in_graph_order(run: RecordingSink) -> None:
    phases = [e.phase for e in run.events if e.type == "phase"]
    assert phases[0] == "plan"
    assert "investigate" in phases
    assert phases.index("write") < phases.index("verify")


def test_tool_calls_are_emitted_with_their_evidence(run: RecordingSink) -> None:
    tool_events = [e for e in run.events if isinstance(e, ToolCallEvent)]
    assert tool_events, "a run always calls at least get_alert"
    assert tool_events[0].tool == "get_alert", "the ledger is bootstrapped from the alert"
    assert all(e.duration_ms >= 0 for e in tool_events)


def test_a_ledger_event_follows_each_evidence_id(run: RecordingSink) -> None:
    """A citation only becomes available because a tool returned it."""
    from_tools = [eid for e in run.events if isinstance(e, ToolCallEvent) for eid in e.evidence_ids]
    from_ledger = [e.evidence_id for e in run.events if isinstance(e, LedgerEvent)]
    assert from_ledger == from_tools


def test_llm_calls_are_emitted_with_role_and_size(run: RecordingSink) -> None:
    llm_events = [e for e in run.events if isinstance(e, LlmCallEvent)]
    assert {"plan", "investigate", "write"} <= {e.role for e in llm_events}
    assert all(e.prompt_chars > 0 for e in llm_events)


def test_levers_report_when_they_decline_to_fire(run: RecordingSink) -> None:
    """The trace only ever noted a lever that changed the verdict."""
    levers = [e for e in run.events if isinstance(e, LeverEvent)]
    assert {"verdict_floor", "thin_window", "lsass_fp"} <= {e.lever_id for e in levers}
    assert any(e.fired is False for e in levers), "a quiet lever is still a reported lever"
    assert all(e.effect is None for e in levers if not e.fired)


def test_verification_is_emitted_once_with_the_final_status(run: RecordingSink) -> None:
    verify_events = [e for e in run.events if isinstance(e, VerifyEvent)]
    assert len(verify_events) == 1, "status is only final once the graph has stopped"
    assert verify_events[0].status in {"passed", "repaired", "degraded"}


def test_stream_and_trace_agree_on_tool_calls(downloader_scenario: Scenario) -> None:
    """The two views are built from one source and must not diverge."""
    sink = RecordingSink()
    result = Investigator(
        llm=_chat_with_a_tool_call(),
        budget=Budget(max_tool_calls=8, max_llm_calls=10),
        progress=sink,
    ).run_scenario(downloader_scenario)

    streamed = [(e.call_seq, e.tool, e.ok) for e in sink.events if isinstance(e, ToolCallEvent)]
    traced = [(c.seq, c.tool, c.ok) for c in result.trace.tool_calls]
    assert streamed == traced


def test_stream_and_trace_agree_on_llm_calls(downloader_scenario: Scenario) -> None:
    sink = RecordingSink()
    result = Investigator(
        llm=_chat_with_a_tool_call(),
        budget=Budget(max_tool_calls=8, max_llm_calls=10),
        progress=sink,
    ).run_scenario(downloader_scenario)

    streamed = [(e.call_seq, e.role) for e in sink.events if isinstance(e, LlmCallEvent)]
    traced = [(c.seq, c.role) for c in result.trace.llm_calls]
    assert streamed == traced


def test_running_without_a_sink_changes_nothing(downloader_scenario: Scenario) -> None:
    """The frozen metrics depend on this: NullSink must not alter the result."""
    observed = Investigator(
        llm=_chat_with_a_tool_call(),
        budget=Budget(max_tool_calls=8, max_llm_calls=10),
        progress=RecordingSink(),
    ).run_scenario(downloader_scenario)
    silent = Investigator(
        llm=_chat_with_a_tool_call(),
        budget=Budget(max_tool_calls=8, max_llm_calls=10),
    ).run_scenario(downloader_scenario)

    assert observed.case_file == silent.case_file
    assert [c.tool for c in observed.trace.tool_calls] == [c.tool for c in silent.trace.tool_calls]
    assert observed.verification is not None and silent.verification is not None
    assert observed.verification.status == silent.verification.status
