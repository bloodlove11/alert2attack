import json

from typer.testing import CliRunner

from alert2attack.cli import app
from alert2attack.domain.events import EventKind
from alert2attack.domain.scenario import SCENARIOS_ROOT, load_scenario

runner = CliRunner()

# Committed datasets are OTRF-only; pick a stable scenario with a process tree.
OTRF = load_scenario(SCENARIOS_ROOT / "otrf_empire_launcher_vbs")
OTRF_ID = OTRF.scenario_id
_TRIGGER = next(e for e in OTRF.events if e.event_id == OTRF.alert.trigger_event_id)
_TREE_PID = next(
    e.pid
    for e in OTRF.events
    if e.kind is EventKind.PROCESS_CREATE and e.pid is not None and e.ppid is not None
)


def test_scenarios_list() -> None:
    result = runner.invoke(app, ["scenarios", "list"])
    assert result.exit_code == 0, result.output
    assert OTRF_ID in result.output
    assert "malicious" in result.output


def test_scenarios_show_hides_gold_by_default() -> None:
    result = runner.invoke(app, ["scenarios", "show", OTRF_ID])
    assert result.exit_code == 0, result.output
    assert "GOLD-MARKER" not in result.output
    assert OTRF.alert.trigger_event_id in result.output
    with_gold = runner.invoke(app, ["scenarios", "show", OTRF_ID, "--gold"])
    assert "GOLD-MARKER" in with_gold.output


def test_tools_lists_schemas() -> None:
    result = runner.invoke(app, ["tools"])
    assert result.exit_code == 0, result.output
    assert "get_process_tree" in result.output and "depth" in result.output


def test_tool_call_prints_result_and_ledger() -> None:
    result = runner.invoke(
        app, ["tool", "get_process_tree", "--scenario", OTRF_ID, f"pid={_TREE_PID}", "depth=1"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["result"]["ok"] is True
    assert isinstance(payload["result"]["data"]["ancestors"], list)
    assert isinstance(payload["ledger"], list)


def test_tool_call_with_bad_args_exits_nonzero() -> None:
    result = runner.invoke(app, ["tool", "get_process", "--scenario", OTRF_ID, "pid=abc"])
    assert result.exit_code == 1
    assert "invalid arguments" in result.output


def test_unknown_scenario_exits_nonzero() -> None:
    result = runner.invoke(app, ["tool", "get_alert", "--scenario", "nope"])
    assert result.exit_code == 2
    assert "nope" in result.output
