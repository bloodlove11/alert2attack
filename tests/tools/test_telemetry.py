import pytest

from alert2attack.domain.scenario import Scenario
from alert2attack.knowledge.base import KnowledgeBase
from alert2attack.store.case_store import CaseStore
from alert2attack.tools.context import EvidenceLedger, ToolContext
from alert2attack.tools.registry import ToolRegistry
from alert2attack.tools.telemetry import register_telemetry_tools


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


@pytest.fixture
def reg() -> ToolRegistry:
    r = ToolRegistry()
    register_telemetry_tools(r)
    return r


def test_registered_names(reg: ToolRegistry) -> None:
    assert reg.names() == [
        "get_alert",
        "get_events_for_process",
        "get_process",
        "get_process_tree",
        "search_events",
    ]


def test_get_alert_returns_trigger_and_window(reg: ToolRegistry, ctx: ToolContext) -> None:
    r = reg.call(ctx, "get_alert", {})
    assert r.ok
    assert r.data["alert"]["rule_id"] == "win_powershell_encoded_command"
    assert r.data["trigger_event"]["event_id"] == "ev-0004"
    assert r.data["window"] == {"start": "2024-03-12T09:55:00Z", "end": "2024-03-12T10:25:00Z"}
    assert r.evidence_ids == ["ev-0004"]


def test_get_process_found_and_missing(reg: ToolRegistry, ctx: ToolContext) -> None:
    r = reg.call(ctx, "get_process", {"pid": 4120})
    assert r.ok and r.data["event_id"] == "ev-0003" and r.evidence_ids == ["ev-0003"]
    assert "ts" in r.data and "user" in r.data
    miss = reg.call(ctx, "get_process", {"pid": 31337})
    assert not miss.ok and miss.error is not None and "31337" in miss.error
    assert miss.evidence_ids == []


def test_get_process_tree_ancestors_and_descendants(reg: ToolRegistry, ctx: ToolContext) -> None:
    r = reg.call(ctx, "get_process_tree", {"pid": 5288, "depth": 3})
    assert r.ok
    assert [a["pid"] for a in r.data["ancestors"]] == [4120, 3344, 1180]  # nearest first
    assert [d["pid"] for d in r.data["descendants"]] == [5304]
    assert r.data["descendants"][0]["depth"] == 1
    assert set(r.evidence_ids) == {"ev-0004", "ev-0003", "ev-0002", "ev-0001", "ev-0008"}
    assert r.truncated is False


def test_get_process_tree_depth_is_bounded(reg: ToolRegistry, ctx: ToolContext) -> None:
    r = reg.call(ctx, "get_process_tree", {"pid": 5288, "depth": 1})
    assert [a["pid"] for a in r.data["ancestors"]] == [4120]
    bad = reg.call(ctx, "get_process_tree", {"pid": 5288, "depth": 9})
    assert not bad.ok


def test_get_events_for_process_with_kind_filter(reg: ToolRegistry, ctx: ToolContext) -> None:
    r = reg.call(ctx, "get_events_for_process", {"pid": 5288})
    assert [e["event_id"] for e in r.data["events"]] == ["ev-0004", "ev-0005", "ev-0006", "ev-0007"]
    assert r.evidence_ids == ["ev-0004", "ev-0005", "ev-0006", "ev-0007"]
    reg_only = reg.call(ctx, "get_events_for_process", {"pid": 5288, "kinds": ["registry_set"]})
    assert [e["event_id"] for e in reg_only.data["events"]] == ["ev-0007"]


def test_search_events_contains_and_truncation(reg: ToolRegistry, ctx: ToolContext) -> None:
    r = reg.call(ctx, "search_events", {"contains": "185.220.101.4"})
    assert {e["event_id"] for e in r.data["events"]} == {"ev-0005", "ev-0010"}
    small = reg.call(ctx, "search_events", {"kind": "process_create", "limit": 2})
    assert len(small.data["events"]) == 2 and small.truncated is True
    assert small.data["next_offset"] == 2


def test_search_events_clamps_time_to_window(reg: ToolRegistry, ctx: ToolContext) -> None:
    r = reg.call(
        ctx,
        "search_events",
        {"since": "2020-01-01T00:00:00Z", "until": "2030-01-01T00:00:00Z", "limit": 50},
    )
    assert r.ok and len(r.data["events"]) == 12
    assert r.data["clamped_to_window"] is True
    assert r.data["since"] == "2024-03-12T09:55:00Z" and r.data["until"] == "2024-03-12T10:25:00Z"


def test_every_returned_event_is_in_ledger(reg: ToolRegistry, ctx: ToolContext) -> None:
    reg.call(ctx, "get_alert", {})
    reg.call(ctx, "get_process_tree", {"pid": 5288, "depth": 2})
    reg.call(ctx, "search_events", {"kind": "network_connect"})
    # depth 2 from 5288: parents 4120 and 3344 (not explorer 1180), child 5304; plus both connects
    assert ctx.ledger.ids() == {"ev-0002", "ev-0003", "ev-0004", "ev-0005", "ev-0008", "ev-0010"}
