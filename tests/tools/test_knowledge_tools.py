import pytest

from alert2attack.domain.scenario import Scenario
from alert2attack.knowledge.base import KnowledgeBase
from alert2attack.store.case_store import CaseStore
from alert2attack.tools import default_registry
from alert2attack.tools.context import EvidenceLedger, ToolContext


@pytest.fixture
def ctx(downloader_scenario: Scenario) -> ToolContext:
    store = CaseStore()
    store.load_case(downloader_scenario.public())
    return ToolContext(
        store=store,
        case_id=downloader_scenario.scenario_id,
        ledger=EvidenceLedger(),
        knowledge=KnowledgeBase.load_default(),
    )


def test_default_registry_has_all_eight_tools() -> None:
    assert default_registry().names() == [
        "decode_powershell",
        "get_alert",
        "get_events_for_process",
        "get_process",
        "get_process_tree",
        "lookup_attack_technique",
        "lookup_sigma_rule",
        "search_events",
    ]


def test_lookup_sigma_rule(ctx: ToolContext) -> None:
    reg = default_registry()
    r = reg.call(ctx, "lookup_sigma_rule", {"rule_id": "win_powershell_encoded_command"})
    assert r.ok
    assert r.data["title"] == "Suspicious Encoded PowerShell Command Line"
    assert r.data["attack_technique_ids"] == ["T1059.001", "T1027"]
    assert r.evidence_ids == ["rule-win_powershell_encoded_command"]
    miss = reg.call(ctx, "lookup_sigma_rule", {"rule_id": "does_not_exist"})
    assert not miss.ok and miss.error is not None and "does_not_exist" in miss.error


def test_lookup_attack_technique(ctx: ToolContext) -> None:
    reg = default_registry()
    r = reg.call(ctx, "lookup_attack_technique", {"technique_id": "t1547.001"})
    assert r.ok and r.data["name"].startswith("Boot or Logon Autostart")
    assert r.evidence_ids == ["attack-T1547.001"]
    assert not reg.call(ctx, "lookup_attack_technique", {"technique_id": "T9999"}).ok
    assert not reg.call(ctx, "lookup_attack_technique", {"technique_id": "1547"}).ok


def test_decode_powershell_tool_is_derived_not_evidence(ctx: ToolContext) -> None:
    reg = default_registry()
    trigger = reg.call(ctx, "get_alert", {}).data["trigger_event"]
    r = reg.call(ctx, "decode_powershell", {"command_line": trigger["command_line"]})
    assert r.ok and r.data["encoded"] is True
    assert "185.220.101.4/a.ps1" in r.data["decoded"]
    assert r.evidence_ids == []
    assert ctx.ledger.ids() == {"ev-0004"}
