import json

from alert2attack.agent.budget import Budget
from alert2attack.agent.investigator import Investigator
from alert2attack.agent.llm import ChatResponse, ScriptedChat, ToolCallRequest
from alert2attack.domain.casefile import Verdict
from alert2attack.domain.scenario import Scenario


def _casefile_json(*, evidence: str = "ev-0004") -> str:
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
                "involved_pids": [],
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


def test_investigator_scripted_end_to_end(downloader_scenario: Scenario) -> None:
    chat = ScriptedChat(
        [
            ChatResponse(content="1. Confirm alert\n2. Expand process tree\n3. Write case file"),
            ChatResponse(
                tool_calls=(
                    ToolCallRequest(id="call_1", name="get_process_tree", arguments={"pid": 5288, "depth": 2}),
                )
            ),
            ChatResponse(content="Ready to write the case file."),
            ChatResponse(content=_casefile_json()),
            ChatResponse(content=_casefile_json()),
            ChatResponse(content=_casefile_json()),
        ]
    )
    result = Investigator(llm=chat, budget=Budget(max_tool_calls=8, max_llm_calls=12)).run_scenario(
        downloader_scenario
    )
    assert result.case_file.verdict is Verdict.MALICIOUS
    assert result.verification is not None
    assert result.verification.passed
    assert 5288 in result.case_file.scope.involved_pids
    assert result.trace.llm_calls  # plan + investigate* + write
    assert result.trace.tool_calls  # get_alert + get_process_tree
    assert "ev-0004" in {eid for c in result.trace.tool_calls for eid in c.evidence_ids}
    roles = [c.role for c in result.trace.llm_calls]
    assert roles[0] == "plan"
    assert "write" in roles


def test_investigator_repairs_then_passes(downloader_scenario: Scenario) -> None:
    bad = json.dumps(
        {
            "verdict": "malicious",
            "confidence": "high",
            "summary": "Bad citation.",
            "timeline": [{"ts": "2024-03-12T10:00:00Z", "text": "x", "evidence": ["ev-9999"]}],
            "techniques": [],
            "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
            "next_actions": [],
            "open_questions": [],
        }
    )
    chat = ScriptedChat(
        [
            ChatResponse(content="plan"),
            ChatResponse(content="ready"),
            ChatResponse(content=bad),
            ChatResponse(content=_casefile_json()),  # repair
            ChatResponse(content=_casefile_json()),
        ]
    )
    result = Investigator(llm=chat, budget=Budget(max_tool_calls=4, max_llm_calls=12)).run_scenario(
        downloader_scenario
    )
    assert result.verification is not None
    assert result.verification.passed
    assert result.verification.repairs_used >= 1
    assert result.verification.pre_repair_errors
    assert result.pre_repair_case_file is not None
    assert result.pre_repair_case_file.timeline[0].evidence == ["ev-9999"]
    assert result.case_file.timeline[0].evidence == ["ev-0004"]
    assert 5288 in result.case_file.scope.involved_pids


def test_investigator_stops_when_tool_budget_exhausted(downloader_scenario: Scenario) -> None:
    # plan consumes 1 tool (get_alert). max_tool_calls=1 → investigate ends without more tools.
    chat = ScriptedChat(
        [
            ChatResponse(content="plan"),
            ChatResponse(content=_casefile_json()),
            ChatResponse(content=_casefile_json()),
            ChatResponse(content=_casefile_json()),
        ]
    )
    result = Investigator(llm=chat, budget=Budget(max_tool_calls=1, max_llm_calls=10)).run_scenario(
        downloader_scenario
    )
    assert result.trace.budget["tool_calls"] == 1
    assert result.trace.budget["tool_exhausted"] is True
    assert [c.tool for c in result.trace.tool_calls] == ["get_alert"]
    assert result.case_file.verdict is Verdict.MALICIOUS
