"""Invariants every committed scenario must satisfy. Fails loudly when someone adds a bad case."""

import pytest

from alert2attack.domain.scenario import SCENARIOS_ROOT, Scenario, iter_scenarios
from alert2attack.knowledge.base import KnowledgeBase
from alert2attack.store.case_store import CaseStore
from alert2attack.tools import default_registry
from alert2attack.tools.context import EvidenceLedger, ToolContext

SCENARIOS = list(iter_scenarios(SCENARIOS_ROOT))
KB = KnowledgeBase.load_default()


def test_dataset_size_and_splits() -> None:
    assert len(SCENARIOS) >= 20
    splits = {s.split for s in SCENARIOS}
    assert splits == {"dev", "test"}
    assert sum(1 for s in SCENARIOS if s.split == "test") >= 6
    origins = {s.origin for s in SCENARIOS}
    assert origins == {"otrf"}


def test_one_scenario_per_gold_verdict_class_exists() -> None:
    verdicts = {s.gold.verdict for s in SCENARIOS if s.gold}
    assert verdicts == {"malicious", "likely_benign", "not_enough_evidence"}


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.scenario_id)
def test_scenario_invariants(scenario: Scenario) -> None:
    assert scenario.gold is not None, "committed scenarios must carry gold"
    ids = {e.event_id for e in scenario.events}
    assert set(scenario.gold.persistence_evidence) <= ids
    assert KB.rule(scenario.alert.rule_id) is not None
    for t in scenario.gold.techniques:
        assert KB.technique(t) is not None, t
    pids = {e.pid for e in scenario.events if e.pid is not None}
    assert set(scenario.gold.key_pids) <= pids
    if scenario.gold.root_pid is not None:
        assert scenario.gold.root_pid in pids
    assert not (set(scenario.gold.acceptable_actions) & set(scenario.gold.unacceptable_actions))
    assert "GOLD-MARKER" in scenario.gold.narrative
    if scenario.origin == "otrf":
        assert scenario.provenance is not None
        assert scenario.provenance.source_sha256 and len(scenario.provenance.source_sha256) == 64


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.scenario_id)
def test_every_scenario_loads_fully_and_tools_reach_the_trigger(scenario: Scenario) -> None:
    store = CaseStore()
    report = store.load_case(scenario.public())
    assert report.loaded == len(scenario.events), "committed scenarios must be fully inside the window"
    ctx = ToolContext(store=store, case_id=scenario.scenario_id, ledger=EvidenceLedger(), knowledge=KB)
    reg = default_registry()
    alert = reg.call(ctx, "get_alert", {})
    assert alert.ok and alert.data["trigger_event"]["event_id"] == scenario.alert.trigger_event_id
    trigger = alert.data["trigger_event"]
    if trigger.get("kind") == "process_create" and trigger.get("pid") is not None:
        tree = reg.call(ctx, "get_process_tree", {"pid": trigger["pid"], "depth": 4})
        assert tree.ok, tree.error
    assert "GOLD-MARKER" not in store.dump_text()
