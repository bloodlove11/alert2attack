import json
from pathlib import Path

from typer.testing import CliRunner

from alert2attack.cli import app
from alert2attack.domain.scenario import SCENARIOS_ROOT, load_scenario

runner = CliRunner()


def test_investigate_scripted(tmp_path: Path) -> None:
    scenario = load_scenario(SCENARIOS_ROOT / "otrf_empire_launcher_vbs")
    eid = scenario.alert.trigger_event_id
    casefile = {
        "verdict": "malicious",
        "confidence": "medium",
        "summary": "OTRF empire launcher activity looks malicious.",
        "timeline": [{"ts": "2020-09-04T20:09:55Z", "text": "encoded powershell", "evidence": [eid]}],
        "techniques": [],
        "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
        "next_actions": [
            {"action": "escalate", "rationale": {"text": "need analyst", "evidence": [eid]}}
        ],
        "open_questions": [],
    }
    responses = [
        {"content": "1. alert 2. write"},
        {"content": "ready"},
        {"content": json.dumps(casefile)},
        {"content": json.dumps(casefile)},
        {"content": json.dumps(casefile)},
    ]
    path = tmp_path / "responses.json"
    path.write_text(json.dumps(responses), encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "investigate",
            "otrf_empire_launcher_vbs",
            "--model",
            "scripted",
            "--responses-json",
            str(path),
            "--max-tools",
            "6",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["case_file"]["verdict"] == "malicious"
    assert payload["trace"]["tool_calls"]
    assert payload["verification"] is not None
    assert payload["verification"]["passed"] is True
    assert payload["trace"]["budget"]["max_tool_calls"] == 6


def test_investigate_scripted_unbounded_budget_by_default(tmp_path: Path) -> None:
    scenario = load_scenario(SCENARIOS_ROOT / "otrf_empire_launcher_vbs")
    eid = scenario.alert.trigger_event_id
    casefile = {
        "verdict": "malicious",
        "confidence": "medium",
        "summary": "OTRF empire launcher activity looks malicious.",
        "timeline": [{"ts": "2020-09-04T20:09:55Z", "text": "encoded powershell", "evidence": [eid]}],
        "techniques": [],
        "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
        "next_actions": [
            {"action": "escalate", "rationale": {"text": "need analyst", "evidence": [eid]}}
        ],
        "open_questions": [],
    }
    responses = [
        {"content": "1. alert 2. write"},
        {"content": "ready"},
        {"content": json.dumps(casefile)},
        {"content": json.dumps(casefile)},
        {"content": json.dumps(casefile)},
    ]
    path = tmp_path / "responses.json"
    path.write_text(json.dumps(responses), encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "investigate",
            "otrf_empire_launcher_vbs",
            "--model",
            "scripted",
            "--responses-json",
            str(path),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    budget = payload["trace"]["budget"]
    assert budget["max_tool_calls"] is None
    assert budget["max_llm_calls"] is None
    assert budget["timeout_s"] is None
    assert budget["tool_exhausted"] is False
    assert budget["llm_exhausted"] is False

