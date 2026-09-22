"""DR-008 / DR-010: deterministic involved_pids hydrate from grounded pids only.

DR-010 restores the DR-008 (#20) known_pids union (trigger pid/target_pid plus
ledger event pid/ppid/target_pid) after DR-009 was reverted. Does not change
metric formulas, protocol, or root_hit.
"""

from __future__ import annotations

import json

from alert2attack.agent.budget import Budget
from alert2attack.agent.investigator import Investigator
from alert2attack.agent.llm import ChatResponse, ScriptedChat
from alert2attack.agent.scope import known_pids_from_store
from alert2attack.domain.casefile import CaseFile, Claim, Scope, Verdict
from alert2attack.domain.events import EventKind
from alert2attack.domain.scenario import SCENARIOS_ROOT, Scenario, load_scenario
from alert2attack.domain.scope import hydrate_involved_pids, pids_from_events
from alert2attack.eval.b0 import B0_MAX_EVENTS, run_b0
from alert2attack.store.case_store import CaseStore
from alert2attack.tools.context import EvidenceLedger, ToolCallRecord


def _casefile(
    *,
    involved_pids: list[int] | None = None,
    root_process: Claim | None = None,
) -> CaseFile:
    return CaseFile(
        verdict=Verdict.LIKELY_BENIGN,
        confidence="low",
        summary="Grounded pid hydrate fixture.",
        scope=Scope(involved_pids=list(involved_pids or []), root_process=root_process),
    )


def _write_json(*, involved_pids: list[int], evidence: str = "ev-0004") -> str:
    return json.dumps(
        {
            "verdict": "malicious",
            "confidence": "high",
            "summary": "Encoded PowerShell downloaded a remote script. Isolate the host.",
            "timeline": [
                {
                    "ts": "2024-03-12T10:00:00Z",
                    "text": "Suspicious encoded PowerShell launched.",
                    "evidence": [evidence],
                }
            ],
            "techniques": [{"technique_id": "T1059.001", "evidence": [evidence], "note": "encoded ps"}],
            "scope": {
                "root_process": {"text": "cmd launched powershell", "evidence": [evidence]},
                "involved_pids": involved_pids,
                "persistence": [],
                "beyond_process": False,
            },
            "next_actions": [
                {
                    "action": "isolate_host",
                    "rationale": {"text": "active download", "evidence": [evidence]},
                }
            ],
            "open_questions": [],
        }
    )


def test_empty_involved_pids_gains_known_trigger_pid() -> None:
    out = hydrate_involved_pids(_casefile(involved_pids=[]), [1244])
    assert out.scope.involved_pids == [1244]


def test_hydrate_does_not_invent_pids_outside_known_set() -> None:
    out = hydrate_involved_pids(_casefile(involved_pids=[]), [1244])
    assert 600 not in out.scope.involved_pids
    assert set(out.scope.involved_pids) <= {1244}


def test_existing_model_pids_are_preserved_even_if_not_in_known_set() -> None:
    out = hydrate_involved_pids(_casefile(involved_pids=[50, 60]), [60, 70])
    assert out.scope.involved_pids == [50, 60, 70]


def test_hydrate_dedupes_and_keeps_stable_order() -> None:
    out = hydrate_involved_pids(_casefile(involved_pids=[10, 20]), [20, 10, 30, 30])
    assert out.scope.involved_pids == [10, 20, 30]


def test_hydrate_does_not_create_root_process() -> None:
    root = Claim(text="vboxservice accessed lsass", evidence=["ev-0001"])
    empty_root = hydrate_involved_pids(_casefile(involved_pids=[]), [1244])
    assert empty_root.scope.root_process is None
    kept = hydrate_involved_pids(_casefile(involved_pids=[], root_process=root), [1244])
    assert kept.scope.root_process == root


def test_pids_from_events_reads_pid_ppid_target_pid(downloader_scenario: Scenario) -> None:
    trigger = next(e for e in downloader_scenario.events if e.event_id == "ev-0004")
    assert trigger.pid == 5288
    assert trigger.ppid == 4120
    found = pids_from_events([trigger])
    assert found == [5288, 4120]


def test_known_pids_from_store_uses_trigger_and_ledger_events(downloader_scenario: Scenario) -> None:
    public = downloader_scenario.public()
    store = CaseStore()
    store.load_case(public)
    ledger = EvidenceLedger()
    ledger.record(
        ToolCallRecord(
            seq=1,
            tool="get_alert",
            args={},
            ok=True,
            evidence_ids=["ev-0004"],
            error=None,
            duration_ms=1.0,
        )
    )
    known = known_pids_from_store(store, public.scenario_id, ledger.ids())
    trigger = store.get_event(public.scenario_id, public.alert.trigger_event_id)
    assert trigger is not None
    assert trigger.pid == 5288
    assert 5288 in known
    assert trigger.ppid in known
    # Network event ev-0005 is not in the ledger — its pid must not appear only from the store.
    assert set(known) <= {trigger.pid, trigger.ppid, trigger.target_pid}


def test_known_pids_do_not_include_store_events_outside_ledger(downloader_scenario: Scenario) -> None:
    public = downloader_scenario.public()
    store = CaseStore()
    store.load_case(public)
    known = known_pids_from_store(store, public.scenario_id, ledger_ids=())
    trigger = store.get_event(public.scenario_id, public.alert.trigger_event_id)
    assert trigger is not None and trigger.pid is not None
    # Trigger pid/target_pid still come from the alert even with an empty ledger.
    assert trigger.pid in known
    explorer = next(e for e in public.events if e.event_id == "ev-0001")
    assert explorer.pid == 1180
    assert 1180 not in known


def test_b0_hydrates_pids_from_inline_dump_events_only(downloader_scenario: Scenario) -> None:
    dump_events = downloader_scenario.events[:B0_MAX_EVENTS]
    dump_pids = set(pids_from_events(dump_events))
    chat = ScriptedChat([ChatResponse(content=_write_json(involved_pids=[]))])
    result = run_b0(downloader_scenario, chat)
    assert 5288 in result.case_file.scope.involved_pids
    assert set(result.case_file.scope.involved_pids) <= dump_pids
    # Explorer pid 1180 is in the dump window for this fixture; a pid that is not
    # on dump events must not appear. Use a sentinel the helper never saw.
    assert 99999 not in result.case_file.scope.involved_pids
    assert result.case_file.scope.root_process is not None  # model-supplied; hydrate must not drop it


def test_agent_write_hydrates_trigger_pid_before_verify(downloader_scenario: Scenario) -> None:
    """Empty model involved_pids still pick up the alert trigger pid (get_alert is always called)."""
    write = _write_json(involved_pids=[])
    chat = ScriptedChat(
        [
            ChatResponse(content="plan"),
            ChatResponse(content="ready"),
            ChatResponse(content=write),
            ChatResponse(content=write),
            ChatResponse(content=write),
        ]
    )
    result = Investigator(llm=chat, budget=Budget(max_tool_calls=4, max_llm_calls=10)).run_scenario(
        downloader_scenario
    )
    trigger = next(e for e in downloader_scenario.events if e.kind is EventKind.PROCESS_CREATE and e.pid == 5288)
    assert trigger.event_id == downloader_scenario.alert.trigger_event_id
    assert 5288 in result.case_file.scope.involved_pids
    assert 99999 not in result.case_file.scope.involved_pids
    assert result.pre_repair_case_file is not None
    assert 5288 in result.pre_repair_case_file.scope.involved_pids


def test_agent_hydrates_lsass_trigger_pid_when_model_omits_root_and_pids() -> None:
    """DR-008: process_access trigger pid is grounded even if root_process is omitted."""
    scenario = load_scenario(SCENARIOS_ROOT / "otrf_cmd_dumping_ntds_dit_file_volume_shadow_copy_benign_lsass")
    eid = scenario.alert.trigger_event_id
    payload = json.dumps(
        {
            "verdict": "likely_benign",
            "confidence": "medium",
            "summary": "LSASS access looks like a known false positive.",
            "timeline": [{"ts": "2023-07-19T19:20:10Z", "text": "lsass access", "evidence": [eid]}],
            "techniques": [],
            "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
            "next_actions": [
                {"action": "close_as_benign", "rationale": {"text": "benign fp", "evidence": [eid]}}
            ],
            "open_questions": [],
        }
    )
    chat = ScriptedChat(
        [
            ChatResponse(content="plan"),
            ChatResponse(content="ready"),
            ChatResponse(content=payload),
            ChatResponse(content=payload),
            ChatResponse(content=payload),
        ]
    )
    result = Investigator(llm=chat, budget=Budget(max_tool_calls=4, max_llm_calls=10)).run_scenario(scenario)
    assert result.case_file.scope.root_process is None
    assert 1244 in result.case_file.scope.involved_pids
    assert 99999 not in result.case_file.scope.involved_pids
