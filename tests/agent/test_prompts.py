"""Write-path prompt contracts (DR-006–DR-007, DR-010 LSASS FP under multi-pid scope).

These lock prompt text only — not eval metrics, scoring, root_hit, or the verifier.
"""

from __future__ import annotations

from alert2attack.agent.llm import ChatResponse, ScriptedChat
from alert2attack.agent.prompts import (
    CASEFILE_JSON_SCHEMA_HINT,
    INVESTIGATE_SYSTEM,
    REPAIR_SYSTEM,
    VERDICT_RUBRIC,
    WRITE_SYSTEM,
    investigate_user,
    repair_user,
    write_user,
)
from alert2attack.domain.scenario import Scenario
from alert2attack.eval.b0 import run_b0


def test_verdict_rubric_asymmetric_safety_forbids_false_benign() -> None:
    text = VERDICT_RUBRIC.lower()
    assert "asymmetric" in text
    assert "likely_benign" in text
    assert "close_as_benign" in text
    assert "audit policy" in text
    assert "credential dump" in text
    assert "lolbin" in text
    assert "persistence" in text
    assert "worse" in text
    assert "not_enough_evidence" in text
    assert "citation rules are unchanged" in text


def test_verdict_rubric_likely_benign_only_for_benign_fp() -> None:
    text = VERDICT_RUBRIC.lower()
    assert "lsass" in text
    assert "handle" in text
    assert "only" in text
    assert "gold-style" in text or "gold style" in text
    assert "never emit likely_benign" in text or "never emit verdict likely_benign" in text


def test_write_system_interpolates_rubric_and_keeps_citation_rules() -> None:
    assert VERDICT_RUBRIC in WRITE_SYSTEM
    assert "ev-NNNN" in WRITE_SYSTEM
    assert "Never invent events" in WRITE_SYSTEM
    assert "close_as_benign" in WRITE_SYSTEM


def test_write_user_checklist_before_json() -> None:
    msg = write_user(
        plan="plan",
        ledger_digest=["ev-0001", "attack-T1218.005"],
        tool_digest="digest",
        attack_technique_candidates=["T1218.005"],
    )
    lowered = msg.lower()
    assert "(a)" in lowered
    assert "(b)" in lowered
    assert "(c)" in lowered
    assert "attack" in lowered
    assert "benign-fp" in lowered or "benign fp" in lowered
    assert "asymmetric" in lowered or "safety" in lowered
    assert "citation rules are unchanged" in lowered
    emit = msg.find("Write the CaseFile JSON now")
    assert emit != -1
    assert msg.index("(a)") < emit
    assert msg.index("(b)") < emit
    assert msg.index("(c)") < emit
    assert msg.index("(d)") < emit
    assert "involved_pids" in lowered
    assert "root pid" in lowered
    assert "do not invent pids" in lowered
    assert "technique candidates explicitly looked up this run" in lowered
    assert "t1218.005" in lowered
    assert "attack-t1218.005" in lowered
    assert "candidates, not automatic findings" in lowered
    assert "observed telemetry supports" in lowered
    assert "omit" in lowered and "speculative" in lowered
    assert "rule-*" in lowered and "alone" in lowered


def test_schema_hint_does_not_contradict_asymmetric_safety() -> None:
    text = CASEFILE_JSON_SCHEMA_HINT.lower()
    assert "likely_benign" in text
    assert "close_as_benign" in text or "asymmetric" in text
    assert "worse" in text or "never" in text


def test_b0_user_hint_shares_asymmetric_safety(downloader_scenario: Scenario) -> None:
    chat = ScriptedChat([ChatResponse(content="{not-json}")])
    run_b0(downloader_scenario, chat)
    assert chat.calls
    system, user = chat.calls[0][0].content or "", chat.calls[0][1].content or ""
    assert WRITE_SYSTEM in system
    lowered = user.lower()
    assert "likely_benign" in lowered
    assert "close_as_benign" in lowered
    assert "audit policy" in lowered or "attack-chain" in lowered or "attack chain" in lowered
    assert "worse" in lowered
    assert "lsass" in lowered
    assert "involved_pids" in lowered
    assert "root_process" in lowered
    assert "do not invent pids" in lowered
    assert "never leave involved_pids empty" in lowered


def _asserts_involved_pids_when_root_claimed(text: str) -> None:
    lowered = text.lower()
    assert "involved_pids" in lowered
    assert "root_process" in lowered or "root pid" in lowered
    assert "never leave involved_pids empty" in lowered or "never empty" in lowered
    assert "invent" in lowered


def test_verdict_rubric_requires_involved_pids_when_root_claimed() -> None:
    _asserts_involved_pids_when_root_claimed(VERDICT_RUBRIC)
    assert "MUST include" in VERDICT_RUBRIC
    assert "ledger" in VERDICT_RUBRIC.lower()
    assert "dump" in VERDICT_RUBRIC.lower()


def test_write_system_requires_grounded_involved_pids() -> None:
    assert VERDICT_RUBRIC in WRITE_SYSTEM
    _asserts_involved_pids_when_root_claimed(WRITE_SYSTEM)
    assert "ledger/tool/dump" in WRITE_SYSTEM.lower()


def test_repair_keeps_involved_pids_when_root_remains() -> None:
    _asserts_involved_pids_when_root_claimed(REPAIR_SYSTEM)
    assert "do not clear involved_pids" in REPAIR_SYSTEM.lower()
    msg = repair_user(case_file_json="{}", errors=[], ledger_digest=["ev-0001"])
    lowered = msg.lower()
    assert "involved_pids" in lowered
    assert "root_process" in lowered
    assert "do not invent pids" in lowered


def test_investigate_prompts_ground_pids_from_tools() -> None:
    text = INVESTIGATE_SYSTEM.lower()
    assert "involved_pids" in text
    assert "never invent pids" in text
    assert "get_process" in text
    assert "economical" not in text
    assert "limited tool" not in text
    msg = investigate_user(plan="plan", ledger_digest=["ev-0001"], last_tool_summary="digest")
    lowered = msg.lower()
    assert "do not invent pids" in lowered
    assert "root" in lowered or "involved" in lowered


def test_schema_hint_requires_involved_pids_when_root_set() -> None:
    text = CASEFILE_JSON_SCHEMA_HINT.lower()
    assert "involved_pids" in text
    assert "root_process" in text
    assert "must include" in text
    assert "invent" in text


def _asserts_lsass_fp_under_multi_pid_scope(text: str) -> None:
    lowered = text.lower()
    assert "lsass" in lowered
    assert "handle" in lowered
    assert "involved_pids" in lowered
    assert "attack mesh" in lowered
    assert "isolate_host" in lowered
    assert "kill_process" in lowered
    assert "likely_benign" in lowered
    assert "worse" in lowered
    assert "not_enough_evidence" in lowered


def test_verdict_rubric_lsass_fp_under_multi_pid_scope() -> None:
    """DR-010: long hydrated involved_pids is not an attack; LSASS FP stays likely_benign/safe."""
    _asserts_lsass_fp_under_multi_pid_scope(VERDICT_RUBRIC)
    text = VERDICT_RUBRIC.lower()
    assert "hydrat" in text  # hydrate / hydrated
    assert "prefer likely_benign" in text or "prefer verdict likely_benign" in text
    assert "false likely_benign" in text or "a false likely_benign" in text
    assert "attack-chain" in text or "attack chain" in text


def test_write_system_lsass_fp_safe_actions_under_multi_pid() -> None:
    assert VERDICT_RUBRIC in WRITE_SYSTEM
    _asserts_lsass_fp_under_multi_pid_scope(WRITE_SYSTEM)


def test_write_user_checklist_covers_multi_pid_lsass_fp() -> None:
    msg = write_user(plan="plan", ledger_digest=["ev-0001"], tool_digest="digest")
    lowered = msg.lower()
    assert "(e)" in lowered
    assert "attack mesh" in lowered
    assert "lsass" in lowered
    assert "isolate_host" in lowered
    assert "kill_process" in lowered
    assert "likely_benign" in lowered
    emit = msg.find("Write the CaseFile JSON now")
    assert emit != -1
    assert msg.index("(e)") < emit


def test_repair_keeps_lsass_fp_verdict_and_safe_actions() -> None:
    _asserts_lsass_fp_under_multi_pid_scope(REPAIR_SYSTEM)
    lowered = REPAIR_SYSTEM.lower()
    assert "do not switch" in lowered or "do not add isolate_host" in lowered
    msg = repair_user(case_file_json="{}", errors=[], ledger_digest=["ev-0001"])
    user = msg.lower()
    assert "attack mesh" in user
    assert "lsass" in user
    assert "isolate_host" in user or "kill_process" in user


def test_schema_hint_lsass_fp_under_multi_pid_scope() -> None:
    _asserts_lsass_fp_under_multi_pid_scope(CASEFILE_JSON_SCHEMA_HINT)
