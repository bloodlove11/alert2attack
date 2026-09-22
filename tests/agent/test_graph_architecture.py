"""Architecture checks for the LangGraph investigate ReAct loop."""

from __future__ import annotations

import json

from alert2attack.agent.budget import Budget
from alert2attack.agent.investigator import Investigator
from alert2attack.agent.llm import ChatResponse, ScriptedChat, ToolCallRequest
from alert2attack.domain.casefile import Verdict
from alert2attack.domain.scenario import SCENARIOS_ROOT, Scenario, load_scenario


def _casefile_json_with(
    *,
    verdict: str,
    technique_id: str,
    technique_evidence: str,
    evidence: str = "ev-0004",
) -> str:
    return json.dumps(
        {
            "verdict": verdict,
            "confidence": "low",
            "summary": "Writer stayed conservative after citing a technique.",
            "timeline": [
                {"ts": "2024-03-12T10:00:00Z", "text": "encoded ps", "evidence": [evidence]},
            ],
            "techniques": [
                {"technique_id": technique_id, "evidence": [technique_evidence], "note": ""},
            ],
            "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
            "next_actions": [
                {"action": "escalate", "rationale": {"text": "review", "evidence": [evidence]}},
            ],
            "open_questions": [],
        }
    )


def _scripted_lookup_then_write(technique_id: str, write_json: str) -> ScriptedChat:
    return ScriptedChat(
        [
            ChatResponse(content="plan: lookup technique then write"),
            ChatResponse(
                tool_calls=(
                    ToolCallRequest(
                        id="atk_1",
                        name="lookup_attack_technique",
                        arguments={"technique_id": technique_id},
                    ),
                )
            ),
            ChatResponse(content="ready to write"),
            ChatResponse(content=write_json),
            ChatResponse(content=write_json),
            ChatResponse(content=write_json),
        ]
    )


def _casefile_json(*, evidence: str = "ev-0004") -> str:
    return json.dumps(
        {
            "verdict": "malicious",
            "confidence": "high",
            "summary": "Encoded PowerShell downloaded a remote script. Isolate the host.",
            "timeline": [
                {"ts": "2024-03-12T10:00:00Z", "text": "encoded ps", "evidence": [evidence]},
            ],
            "techniques": [],
            "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
            "next_actions": [
                {"action": "isolate_host", "rationale": {"text": "download", "evidence": [evidence]}},
            ],
            "open_questions": [],
        }
    )


def _casefile_json_without_techniques(*, verdict: str = "not_enough_evidence") -> str:
    return json.dumps(
        {
            "verdict": verdict,
            "confidence": "low",
            "summary": "Telemetry remains ambiguous after reviewing a technique candidate.",
            "timeline": [
                {"ts": "2024-03-12T10:00:00Z", "text": "encoded ps", "evidence": ["ev-0004"]},
            ],
            "techniques": [],
            "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
            "next_actions": [
                {"action": "escalate", "rationale": {"text": "review", "evidence": ["ev-0004"]}},
            ],
            "open_questions": [],
        }
    )


def test_investigate_keeps_tool_results_in_message_thread(downloader_scenario: Scenario) -> None:
    """Second investigate LLM turn must see prior tool results as role=tool messages."""
    chat = ScriptedChat(
        [
            ChatResponse(content="plan: tree then stop"),
            ChatResponse(
                tool_calls=(
                    ToolCallRequest(id="call_1", name="get_process_tree", arguments={"pid": 5288, "depth": 1}),
                )
            ),
            ChatResponse(content="enough evidence"),
            ChatResponse(content=_casefile_json()),
            ChatResponse(content=_casefile_json()),
            ChatResponse(content=_casefile_json()),
        ]
    )
    Investigator(llm=chat, budget=Budget(max_tool_calls=8, max_llm_calls=10)).run_scenario(downloader_scenario)

    # call 0 = plan, call 1 = first investigate, call 2 = second investigate, call 3 = write
    assert len(chat.calls) >= 3
    second_investigate = chat.calls[2]
    roles = [m.role for m in second_investigate]
    assert "tool" in roles
    tool_msgs = [m for m in second_investigate if m.role == "tool"]
    assert tool_msgs[0].tool_call_id == "call_1"
    assert "get_process_tree" in (tool_msgs[0].content or "")


def test_duplicate_tool_calls_end_loop_instead_of_spinning(downloader_scenario: Scenario) -> None:
    dup = ChatResponse(
        tool_calls=(ToolCallRequest(id="d1", name="get_process_tree", arguments={"pid": 5288, "depth": 1}),)
    )
    chat = ScriptedChat(
        [
            ChatResponse(content="plan"),
            dup,  # execute once
            dup,  # duplicate → stop
            ChatResponse(content=_casefile_json()),
            ChatResponse(content=_casefile_json()),
            ChatResponse(content=_casefile_json()),
        ]
    )
    result = Investigator(llm=chat, budget=Budget(max_tool_calls=8, max_llm_calls=10)).run_scenario(
        downloader_scenario
    )
    tree_calls = [c for c in result.trace.tool_calls if c.tool == "get_process_tree"]
    assert len(tree_calls) == 1
    assert any("duplicate" in n for n in result.trace.notes)


def test_skip_plan_ablation(downloader_scenario: Scenario) -> None:
    chat = ScriptedChat(
        [
            # no plan LLM — first response is investigate
            ChatResponse(content="ready"),
            ChatResponse(content=_casefile_json()),
            ChatResponse(content=_casefile_json()),
            ChatResponse(content=_casefile_json()),
        ]
    )
    result = Investigator(
        llm=chat,
        budget=Budget(max_tool_calls=4, max_llm_calls=8),
        skip_plan=True,
    ).run_scenario(downloader_scenario)
    assert result.case_file.verdict is Verdict.MALICIOUS
    assert result.verification is not None and result.verification.passed
    assert any(c.role == "plan" for c in result.trace.llm_calls) is False
    assert any("skip_plan" in n for n in result.trace.notes)
    assert any(c.tool == "get_alert" for c in result.trace.tool_calls)


def test_budget_gates_get_alert(downloader_scenario: Scenario) -> None:
    chat = ScriptedChat(
        [
            ChatResponse(content=_casefile_json()),  # write only
        ]
    )
    # Zero tool budget: bootstrap get_alert must not hit the registry.
    # max_repairs=0 → degrade without extra LLM calls when citations fail.
    result = Investigator(
        llm=chat,
        budget=Budget(max_tool_calls=0, max_llm_calls=4),
        skip_plan=True,
        max_repairs=0,
    ).run_scenario(downloader_scenario)
    assert result.trace.tool_calls == []
    assert result.verification is not None
    assert result.verification.status == "degraded"


def test_verify_floors_nee_when_high_sev_technique_survives(downloader_scenario: Scenario) -> None:
    raw = _casefile_json_with(
        verdict="not_enough_evidence",
        technique_id="T1053.005",
        technique_evidence="attack-T1053.005",
    )
    result = Investigator(
        llm=_scripted_lookup_then_write("T1053.005", raw),
        budget=Budget(max_tool_calls=8, max_llm_calls=10),
    ).run_scenario(downloader_scenario)
    assert result.case_file.verdict is Verdict.MALICIOUS
    assert result.pre_repair_case_file is not None
    assert result.pre_repair_case_file.verdict is Verdict.NOT_ENOUGH_EVIDENCE
    assert any("verdict_floor" in n for n in result.trace.notes)


def test_verify_does_not_floor_execution_only_technique(downloader_scenario: Scenario) -> None:
    raw = _casefile_json_with(
        verdict="not_enough_evidence",
        technique_id="T1059.001",
        technique_evidence="attack-T1059.001",
    )
    result = Investigator(
        llm=_scripted_lookup_then_write("T1059.001", raw),
        budget=Budget(max_tool_calls=8, max_llm_calls=10),
    ).run_scenario(downloader_scenario)
    assert result.case_file.verdict is Verdict.NOT_ENOUGH_EVIDENCE
    assert not any("verdict_floor" in n for n in result.trace.notes)


def test_write_receives_attack_candidates_from_this_run(downloader_scenario: Scenario) -> None:
    raw = _casefile_json_without_techniques()
    chat = _scripted_lookup_then_write("T1053.005", raw)

    Investigator(
        llm=chat,
        budget=Budget(max_tool_calls=8, max_llm_calls=10),
        max_repairs=0,
    ).run_scenario(downloader_scenario)

    write_user_message = next(m.content or "" for m in chat.calls[3] if m.role == "user")
    assert "T1053.005 (evidence attack-T1053.005)" in write_user_message
    assert "candidates, not automatic findings" in write_user_message


def test_rejected_attack_candidate_is_not_projected_or_floored(downloader_scenario: Scenario) -> None:
    raw = _casefile_json_without_techniques()
    result = Investigator(
        llm=_scripted_lookup_then_write("T1053.005", raw),
        budget=Budget(max_tool_calls=8, max_llm_calls=10),
        max_repairs=0,
    ).run_scenario(downloader_scenario)

    assert result.case_file.techniques == []
    assert result.case_file.verdict is Verdict.NOT_ENOUGH_EVIDENCE
    assert not any("verdict_floor" in note for note in result.trace.notes)


def test_investigate_stops_to_reserve_write_llm(downloader_scenario: Scenario) -> None:
    chat = ScriptedChat(
        [
            ChatResponse(content="plan: one tool then write"),
            ChatResponse(
                tool_calls=(
                    ToolCallRequest(
                        id="call_1",
                        name="get_process_tree",
                        arguments={"pid": 5288, "depth": 1},
                    ),
                )
            ),
            ChatResponse(content=_casefile_json()),
            ChatResponse(content=_casefile_json()),
            ChatResponse(content=_casefile_json()),
        ]
    )
    result = Investigator(
        llm=chat,
        budget=Budget(max_tool_calls=8, max_llm_calls=4),
        max_repairs=0,
    ).run_scenario(downloader_scenario)

    assert any("reserve write" in note for note in result.trace.notes)
    assert "write" in [call.role for call in result.trace.llm_calls]
    assert result.case_file is not None


def test_write_accepts_casefile_json_with_extras_and_missing_confidence(
    downloader_scenario: Scenario,
) -> None:
    messy = json.dumps(
        {
            "case_id": "case-001",
            "case_name": "Potential PowerShell Command Execution",
            "verdict": "not_enough_evidence",
            "summary": "Evidence does not clearly establish an attack technique.",
            "timeline": [
                {
                    "ts": "2024-03-12T10:00:00Z",
                    "text": "encoded ps",
                    "evidence": ["ev-0004"],
                }
            ],
            "techniques": [],
            "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
            "next_actions": [
                {
                    "action": "escalate",
                    "rationale": {"text": "needs review", "evidence": ["ev-0004"]},
                }
            ],
            "open_questions": [],
        }
    )
    chat = ScriptedChat(
        [
            ChatResponse(content="plan"),
            ChatResponse(content="ready to write"),
            ChatResponse(content=messy),
            ChatResponse(content=messy),
            ChatResponse(content=messy),
        ]
    )
    result = Investigator(
        llm=chat,
        budget=Budget(max_tool_calls=4, max_llm_calls=8),
        max_repairs=0,
    ).run_scenario(downloader_scenario)

    assert result.case_file.verdict is Verdict.NOT_ENOUGH_EVIDENCE
    assert result.case_file.confidence == "low"
    assert result.case_file.techniques == []
    assert not any("parse failed twice" in note for note in result.trace.notes)


def test_write_skips_parse_on_empty_first_response(downloader_scenario: Scenario) -> None:
    chat = ScriptedChat(
        [
            ChatResponse(content="ready"),
            ChatResponse(content=""),
        ]
    )
    result = Investigator(
        llm=chat,
        budget=Budget(max_tool_calls=4, max_llm_calls=8),
        skip_plan=True,
        max_repairs=0,
    ).run_scenario(downloader_scenario)
    assert any("write: skipped parse (budget exhausted or empty)" in n for n in result.trace.notes)
    assert result.case_file.verdict is Verdict.NOT_ENOUGH_EVIDENCE
    assert "could not produce a reliable case file" in result.case_file.summary
    assert not any("parse failed" in n for n in result.trace.notes)


def test_write_notes_parse_fail_then_budget_exhausted(downloader_scenario: Scenario) -> None:
    # skip_plan + max_llm=1: investigate reserves write; first LLM is write; retry is budget.
    chat = ScriptedChat([ChatResponse(content="not json at all")])
    result = Investigator(
        llm=chat,
        budget=Budget(max_tool_calls=4, max_llm_calls=1),
        skip_plan=True,
        max_repairs=0,
    ).run_scenario(downloader_scenario)
    assert any("write: parse failed once then budget exhausted" in n for n in result.trace.notes)
    assert result.case_file.verdict is Verdict.NOT_ENOUGH_EVIDENCE
    assert result.case_file.summary.startswith("Investigation could not produce")


def test_write_keeps_casefile_when_summary_has_false_periods(downloader_scenario: Scenario) -> None:
    summary = (
        "mshta.exe executed inline JavaScript that retrieved and invoked a remote "
        "scriptlet, matching T1218.005 proxy execution. The activity occurred on "
        "WORKSTATION5 under WORKSTATION5\\wardog and used the referenced Atomic "
        "Red Team payload."
    )
    raw = json.dumps(
        {
            "verdict": "malicious",
            "confidence": "high",
            "summary": summary,
            "timeline": [
                {"ts": "2024-03-12T10:00:00Z", "text": "mshta proxy exec", "evidence": ["ev-0004"]},
            ],
            "techniques": [
                {
                    "technique_id": "T1218.005",
                    "evidence": ["ev-0004"],
                    "note": "mshta",
                }
            ],
            "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
            "next_actions": [
                {"action": "isolate_host", "rationale": {"text": "remote sct", "evidence": ["ev-0004"]}},
            ],
            "open_questions": [],
        }
    )
    chat = ScriptedChat(
        [
            ChatResponse(content="ready"),
            ChatResponse(content=raw),
        ]
    )
    result = Investigator(
        llm=chat,
        budget=Budget(max_tool_calls=4, max_llm_calls=8),
        skip_plan=True,
        max_repairs=0,
    ).run_scenario(downloader_scenario)
    assert not any("parse failed" in n for n in result.trace.notes)
    assert result.case_file.verdict is Verdict.MALICIOUS
    assert "could not produce a reliable case file" not in result.case_file.summary
    assert result.case_file.summary == summary
    assert result.case_file.techniques[0].technique_id == "T1218.005"


def test_write_clips_four_real_sentences_instead_of_stubbing(downloader_scenario: Scenario) -> None:
    raw = json.dumps(
        {
            "verdict": "malicious",
            "confidence": "high",
            "summary": "One claim. Two claim. Three claim. Four claim.",
            "timeline": [
                {"ts": "2024-03-12T10:00:00Z", "text": "encoded ps", "evidence": ["ev-0004"]},
            ],
            "techniques": [],
            "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
            "next_actions": [
                {"action": "escalate", "rationale": {"text": "review", "evidence": ["ev-0004"]}},
            ],
            "open_questions": [],
        }
    )
    chat = ScriptedChat(
        [
            ChatResponse(content="ready"),
            ChatResponse(content=raw),
        ]
    )
    result = Investigator(
        llm=chat,
        budget=Budget(max_tool_calls=4, max_llm_calls=8),
        skip_plan=True,
        max_repairs=0,
    ).run_scenario(downloader_scenario)
    assert not any("parse failed" in n for n in result.trace.notes)
    assert result.case_file.verdict is Verdict.MALICIOUS
    assert result.case_file.summary == "One claim. Two claim. Three claim."
    assert "could not produce a reliable case file" not in result.case_file.summary


def _mshta_proxy_write_json(*, evidence: str) -> str:
    return json.dumps(
        {
            "verdict": "malicious",
            "confidence": "high",
            "summary": "Mshta executed a remote scriptlet matching T1218.005 proxy execution.",
            "timeline": [
                {"ts": "2020-10-22T06:21:37.849000Z", "text": "mshta sct", "evidence": [evidence]},
            ],
            "techniques": [
                {"technique_id": "T1218.005", "evidence": ["attack-T1218.005"], "note": "mshta"},
            ],
            "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
            "next_actions": [
                {"action": "isolate_host", "rationale": {"text": "remote sct", "evidence": [evidence]}},
            ],
            "open_questions": [],
        }
    )


def _scripted_skip_plan_lookup_write(technique_id: str, write_json: str) -> ScriptedChat:
    return ScriptedChat(
        [
            ChatResponse(
                tool_calls=(
                    ToolCallRequest(
                        id="atk_1",
                        name="lookup_attack_technique",
                        arguments={"technique_id": technique_id},
                    ),
                )
            ),
            ChatResponse(content="ready to write"),
            ChatResponse(content=write_json),
            ChatResponse(content=write_json),
            ChatResponse(content=write_json),
        ]
    )


def test_thin_nee_twin_write_is_capped_after_floor() -> None:
    scenario = load_scenario(SCENARIOS_ROOT / "otrf_cmd_mshta_javascript_getobject_sct_nee")
    raw = _mshta_proxy_write_json(evidence="ev-0001")
    result = Investigator(
        llm=_scripted_skip_plan_lookup_write("T1218.005", raw),
        budget=Budget(max_tool_calls=8, max_llm_calls=10),
        skip_plan=True,
        max_repairs=0,
    ).run_scenario(scenario)
    assert result.pre_repair_case_file is not None
    assert result.pre_repair_case_file.verdict is Verdict.MALICIOUS
    assert result.case_file.verdict is Verdict.NOT_ENOUGH_EVIDENCE
    assert any("thin_window" in note for note in result.trace.notes)


def test_full_window_mshta_twin_is_not_capped() -> None:
    scenario = load_scenario(SCENARIOS_ROOT / "otrf_cmd_mshta_javascript_getobject_sct")
    raw = _mshta_proxy_write_json(evidence="ev-0012")
    result = Investigator(
        llm=_scripted_skip_plan_lookup_write("T1218.005", raw),
        budget=Budget(max_tool_calls=8, max_llm_calls=10),
        skip_plan=True,
        max_repairs=0,
    ).run_scenario(scenario)
    assert result.case_file.verdict is Verdict.MALICIOUS
    assert not any("thin_window" in note for note in result.trace.notes)


def _lsass_write_json(*, evidence: str, verdict: str = "malicious") -> str:
    return json.dumps(
        {
            "verdict": verdict,
            "confidence": "high",
            "summary": "LSASS memory was accessed; isolate the host.",
            "timeline": [
                {"ts": "2022-08-18T13:55:57.835000Z", "text": "lsass access", "evidence": [evidence]},
            ],
            "techniques": [],
            "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
            "next_actions": [
                {"action": "isolate_host", "rationale": {"text": "lsass access", "evidence": [evidence]}},
            ],
            "open_questions": [],
        }
    )


def test_lsass_fp_write_is_capped_and_containment_stripped() -> None:
    scenario = load_scenario(
        SCENARIOS_ROOT / "otrf_auditpol_system_user_auditpolicy_modification_benign_lsass"
    )
    raw = _lsass_write_json(evidence="ev-0001")
    result = Investigator(
        llm=ScriptedChat(
            [
                ChatResponse(content="ready"),
                ChatResponse(content=raw),
            ]
        ),
        budget=Budget(max_tool_calls=4, max_llm_calls=8),
        skip_plan=True,
        max_repairs=0,
    ).run_scenario(scenario)
    assert result.pre_repair_case_file is not None
    assert result.pre_repair_case_file.verdict is Verdict.MALICIOUS
    assert result.case_file.verdict is Verdict.LIKELY_BENIGN
    assert all(a.action.value != "isolate_host" for a in result.case_file.next_actions)
    assert any("lsass_fp" in note for note in result.trace.notes)


def test_lsass_dumpert_write_is_not_capped() -> None:
    scenario = load_scenario(SCENARIOS_ROOT / "otrf_cmd_lsass_memory_dumpert_syscalls")
    raw = _lsass_write_json(evidence="ev-0029")
    result = Investigator(
        llm=ScriptedChat(
            [
                ChatResponse(content="ready"),
                ChatResponse(content=raw),
            ]
        ),
        budget=Budget(max_tool_calls=4, max_llm_calls=8),
        skip_plan=True,
        max_repairs=0,
    ).run_scenario(scenario)
    assert result.case_file.verdict is Verdict.MALICIOUS
    assert any(a.action.value == "isolate_host" for a in result.case_file.next_actions)
    assert not any("lsass_fp" in note for note in result.trace.notes)


def test_lsass_logonpasswords_empire_whoami_is_not_capped() -> None:
    scenario = load_scenario(SCENARIOS_ROOT / "otrf_empire_mimikatz_logonpasswords")
    raw = _lsass_write_json(evidence="ev-0018")
    result = Investigator(
        llm=ScriptedChat(
            [
                ChatResponse(content="ready"),
                ChatResponse(content=raw),
            ]
        ),
        budget=Budget(max_tool_calls=4, max_llm_calls=8),
        skip_plan=True,
        max_repairs=0,
    ).run_scenario(scenario)
    assert result.case_file.verdict is Verdict.MALICIOUS
    assert any(a.action.value == "isolate_host" for a in result.case_file.next_actions)
    assert not any("lsass_fp" in note for note in result.trace.notes)


def test_write_notes_parse_failed_twice(downloader_scenario: Scenario) -> None:
    chat = ScriptedChat(
        [
            ChatResponse(content="ready"),
            ChatResponse(content="not json at all"),
            ChatResponse(content="still not json"),
        ]
    )
    result = Investigator(
        llm=chat,
        budget=Budget(max_tool_calls=4, max_llm_calls=8),
        skip_plan=True,
        max_repairs=0,
    ).run_scenario(downloader_scenario)
    assert any("write: parse failed twice" in n for n in result.trace.notes)
    assert result.case_file.verdict is Verdict.NOT_ENOUGH_EVIDENCE


def test_repair_keeps_prior_case_file_when_parse_fails(downloader_scenario: Scenario) -> None:
    bad = json.dumps(
        {
            "verdict": "malicious",
            "confidence": "high",
            "summary": "Bad citation from write.",
            "timeline": [{"ts": "2024-03-12T10:00:00Z", "text": "x", "evidence": ["ev-9999"]}],
            "techniques": [],
            "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
            "next_actions": [],
            "open_questions": [],
        }
    )
    chat = ScriptedChat(
        [
            ChatResponse(content="ready"),
            ChatResponse(content=bad),
            ChatResponse(content="not json at all"),
        ]
    )
    result = Investigator(
        llm=chat,
        budget=Budget(max_tool_calls=4, max_llm_calls=12),
        skip_plan=True,
        max_repairs=1,
    ).run_scenario(downloader_scenario)
    assert any("keeping prior case file" in n for n in result.trace.notes)
    assert result.pre_repair_case_file is not None
    assert result.pre_repair_case_file.summary == "Bad citation from write."
    assert result.pre_repair_case_file.timeline[0].evidence == ["ev-9999"]
