"""EXP-002 lever 5: thin-window abstain ceiling for NEE twins."""

from __future__ import annotations

from alert2attack.agent.thin_window import apply_thin_window_ceiling, is_thin_trigger_window
from alert2attack.agent.verdict_floor import apply_verdict_floor
from alert2attack.domain.casefile import CaseFile, TechniqueClaim, Verdict
from alert2attack.domain.events import Event, EventKind
from alert2attack.domain.scenario import SCENARIOS_ROOT, iter_scenarios
from alert2attack.knowledge.base import KnowledgeBase


def _pc(eid: str, pid: int) -> Event:
    return Event(
        event_id=eid,
        kind=EventKind.PROCESS_CREATE,
        ts="2020-10-22T06:21:37.849000Z",
        host="WORKSTATION5",
        pid=pid,
        image="C:\\Windows\\System32\\mshta.exe",
    )


def test_one_or_two_process_creates_are_thin() -> None:
    assert is_thin_trigger_window([_pc("ev-0001", 10076)]) is True
    assert is_thin_trigger_window([_pc("ev-0001", 10196), _pc("ev-0002", 10076)]) is True


def test_empty_or_followon_is_not_thin() -> None:
    assert is_thin_trigger_window([]) is False
    load = Event(
        event_id="ev-0002",
        kind=EventKind.IMAGE_LOAD,
        ts="2020-10-22T06:21:37.849000Z",
        host="WORKSTATION5",
        pid=10076,
        image="C:\\Windows\\System32\\mshta.exe",
        target_path="C:\\Windows\\System32\\ntdll.dll",
    )
    assert is_thin_trigger_window([_pc("ev-0001", 10076), load]) is False
    assert is_thin_trigger_window([_pc("ev-0001", 1), _pc("ev-0002", 2), _pc("ev-0003", 3)]) is False


def test_ceiling_caps_malicious_on_thin_window() -> None:
    cf = CaseFile(verdict="malicious", confidence="high", summary="Mshta proxy execution observed.")
    out = apply_thin_window_ceiling(cf, [_pc("ev-0001", 10076)])
    assert out.verdict is Verdict.NOT_ENOUGH_EVIDENCE
    assert any("trigger" in q.lower() for q in out.open_questions)
    assert out.summary == cf.summary


def test_ceiling_leaves_full_window_and_existing_nee() -> None:
    load = Event(
        event_id="ev-0002",
        kind=EventKind.IMAGE_LOAD,
        ts="2020-10-22T06:21:37.849000Z",
        host="WORKSTATION5",
        pid=10076,
        image="C:\\Windows\\System32\\mshta.exe",
        target_path="C:\\Windows\\System32\\ntdll.dll",
    )
    malicious = CaseFile(verdict="malicious", confidence="high", summary="Mshta proxy execution observed.")
    assert apply_thin_window_ceiling(malicious, [_pc("ev-0001", 10076), load]).verdict is Verdict.MALICIOUS
    nee = CaseFile(verdict="not_enough_evidence", confidence="low", summary="Trigger only.")
    assert apply_thin_window_ceiling(nee, [_pc("ev-0001", 10076)]).verdict is Verdict.NOT_ENOUGH_EVIDENCE


def test_ceiling_beats_verdict_floor_on_thin_t1218() -> None:
    kb = KnowledgeBase.load_default()
    cf = CaseFile(
        verdict="not_enough_evidence",
        confidence="low",
        summary="Mshta proxy execution observed.",
        techniques=[TechniqueClaim(technique_id="T1218.005", evidence=["attack-T1218.005"])],
    )
    floored = apply_verdict_floor(cf, kb)
    assert floored.verdict is Verdict.MALICIOUS
    out = apply_thin_window_ceiling(floored, [_pc("ev-0001", 10076)])
    assert out.verdict is Verdict.NOT_ENOUGH_EVIDENCE


def test_catalog_nee_twins_are_thin_and_malicious_are_not() -> None:
    thin_nee = []
    fat_malicious = []
    for scenario in iter_scenarios(SCENARIOS_ROOT):
        assert scenario.gold is not None
        thin = is_thin_trigger_window(scenario.events)
        if scenario.gold.verdict == "not_enough_evidence":
            assert thin, scenario.scenario_id
            thin_nee.append(scenario.scenario_id)
        if scenario.gold.verdict == "malicious":
            assert not thin, scenario.scenario_id
            fat_malicious.append(scenario.scenario_id)
    assert any(sid.endswith("_nee") for sid in thin_nee)
    assert fat_malicious
