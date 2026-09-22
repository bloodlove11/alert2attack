from datetime import UTC, datetime
from pathlib import Path

import pytest

from alert2attack.domain.events import EventKind
from alert2attack.domain.scenario import Scenario, load_scenario
from alert2attack.store.case_store import CaseNotFound, CaseStore


@pytest.fixture
def store(downloader_scenario: Scenario) -> CaseStore:
    s = CaseStore()
    s.load_case(downloader_scenario.public())
    return s


CASE = "enc_ps_downloader_001"


def test_refuses_gold(downloader_scenario: Scenario) -> None:
    with pytest.raises(ValueError, match="gold"):
        CaseStore().load_case(downloader_scenario)


def test_store_contains_no_gold_text(downloader_scenario: Scenario, tmp_path: Path) -> None:
    db = tmp_path / "case.sqlite"
    s = CaseStore(db)
    s.load_case(downloader_scenario.public())
    assert "GOLD-MARKER" not in s.dump_text()
    assert "GOLD-MARKER" not in db.read_bytes().decode("latin-1")


def test_load_report_and_case_ids(store: CaseStore) -> None:
    assert store.case_ids() == [CASE]


def test_drops_out_of_window_and_other_host(scenario_dir: Path) -> None:
    sc = load_scenario(scenario_dir).public()
    report = CaseStore().load_case(sc)
    assert report.loaded == 2
    assert report.dropped_out_of_window == 1
    assert report.dropped_other_host == 1


def test_alert_and_window(store: CaseStore) -> None:
    alert = store.get_alert(CASE)
    assert alert.trigger_event_id == "ev-0004"
    start, end = store.get_window(CASE)
    assert start == datetime(2024, 3, 12, 9, 55, tzinfo=UTC)
    assert end == datetime(2024, 3, 12, 10, 25, tzinfo=UTC)


def test_unknown_case_raises(store: CaseStore) -> None:
    with pytest.raises(CaseNotFound):
        store.get_alert("nope")


def test_get_event_roundtrips_full_model(store: CaseStore, downloader_scenario: Scenario) -> None:
    original = next(e for e in downloader_scenario.events if e.event_id == "ev-0004")
    assert store.get_event(CASE, "ev-0004") == original
    assert store.get_event(CASE, "ev-9999") is None


def test_find_process_and_children(store: CaseStore) -> None:
    ps = store.find_process(CASE, 5288)
    assert ps is not None and ps.image is not None and ps.image.endswith("powershell.exe")
    assert store.find_process(CASE, 424242) is None
    kids = store.children(CASE, 5288)
    assert [k.pid for k in kids] == [5304]


def test_query_by_kind_pid_and_time(store: CaseStore) -> None:
    net = store.query_events(CASE, kinds=[EventKind.NETWORK_CONNECT])
    assert [e.event_id for e in net] == ["ev-0005", "ev-0010"]
    mine = store.query_events(CASE, pid=5288)
    assert [e.event_id for e in mine] == ["ev-0004", "ev-0005", "ev-0006", "ev-0007"]
    late = store.query_events(CASE, since=datetime(2024, 3, 12, 10, 5, tzinfo=UTC))
    assert [e.event_id for e in late] == ["ev-0011", "ev-0012"]
    early = store.query_events(CASE, until=datetime(2024, 3, 12, 9, 58, tzinfo=UTC))
    assert [e.event_id for e in early] == ["ev-0001", "ev-0002"]


def test_query_contains_is_case_insensitive_and_escapes_like(store: CaseStore) -> None:
    hits = store.query_events(CASE, contains="INVOICE_Q1")
    assert {e.event_id for e in hits} == {"ev-0003", "ev-0004"}
    assert store.query_events(CASE, contains="%") == []
    assert store.query_events(CASE, contains="_") != []  # literal underscore in Invoice_Q1
    assert store.query_events(CASE, contains="185.220.101.4") != []


def test_query_pagination(store: CaseStore) -> None:
    page1 = store.query_events(CASE, limit=5)
    page2 = store.query_events(CASE, limit=5, offset=5)
    page3 = store.query_events(CASE, limit=5, offset=10)
    ids = [e.event_id for e in page1 + page2 + page3]
    assert ids == [f"ev-{i:04d}" for i in range(1, 13)]
