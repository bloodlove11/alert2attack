"""Scenario read routes: queue, detail, telemetry paging."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from alert2attack.api.app import create_app
from alert2attack.api.scenarios import ScenarioNotFound, public_scenario
from alert2attack.domain.scenario import SCENARIOS_ROOT, load_scenario
from alert2attack.store.case_store import encode_event_cursor

SCENARIO = "otrf_empire_launcher_vbs"


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


# -- queue --------------------------------------------------------------------


def test_lists_the_committed_corpus(client: TestClient) -> None:
    rows = client.get("/scenarios").json()
    assert len(rows) == len(list(SCENARIOS_ROOT.glob("*/manifest.yaml")))
    assert {r["scenario_id"] for r in rows} >= {SCENARIO}
    row = next(r for r in rows if r["scenario_id"] == SCENARIO)
    assert row["host"] == "WORKSTATION5.theshire.local"
    assert row["severity"] == "high"
    assert row["rule_title"] == "Suspicious Encoded PowerShell Command Line"


def test_queue_is_ordered_newest_alert_first(client: TestClient) -> None:
    fired = [r["fired_at"] for r in client.get("/scenarios").json()]
    assert fired == sorted(fired, reverse=True)


def test_filters_by_split(client: TestClient) -> None:
    rows = client.get("/scenarios?split=test").json()
    assert rows and all(r["split"] == "test" for r in rows)
    assert len(rows) < len(client.get("/scenarios").json())


def test_filters_by_severity(client: TestClient) -> None:
    rows = client.get("/scenarios?severity=high").json()
    assert rows and all(r["severity"] == "high" for r in rows)


def test_free_text_matches_id_title_and_host(client: TestClient) -> None:
    assert client.get("/scenarios?q=mimikatz").json()
    assert client.get("/scenarios?q=encoded+powershell").json()
    assert client.get("/scenarios?q=theshire").json()
    assert client.get("/scenarios?q=zzzz-no-such-thing").json() == []


def test_unknown_filter_value_is_rejected(client: TestClient) -> None:
    assert client.get("/scenarios?split=production").status_code == 422


# -- detail -------------------------------------------------------------------


def test_detail_reports_the_boxed_window(client: TestClient) -> None:
    body = client.get(f"/scenarios/{SCENARIO}").json()
    scenario = load_scenario(SCENARIOS_ROOT / SCENARIO)
    assert body["event_count"] == len(scenario.events)
    assert body["trigger_event_id"] == scenario.alert.trigger_event_id
    assert body["window_start"] < body["window_end"]


def test_unknown_scenario_is_404(client: TestClient) -> None:
    resp = client.get("/scenarios/no_such_scenario")
    assert resp.status_code == 404
    assert "no_such_scenario" in resp.json()["detail"]


# A bare ".." is resolved away by the HTTP client before dispatch, so it would test
# httpx rather than this route. These are values that actually reach the handler.
@pytest.mark.parametrize(
    "bad_id",
    ["OTRF_UPPER", "with-dash", "with.dot", "with%20space", "..%2f..%2fconftest"],
)
def test_scenario_id_is_constrained_before_it_reaches_the_filesystem(
    client: TestClient, bad_id: str
) -> None:
    """scenario_id is a directory name. Anything outside [a-z0-9_] never gets there."""
    resp = client.get(f"/scenarios/{bad_id}")
    assert resp.status_code in {404, 422}, resp.text
    assert "manifest" not in resp.text.lower()


def test_loader_refuses_to_escape_the_scenarios_root() -> None:
    """Defence in depth: the pattern is the guard, but the loader must not help."""
    for escape in ("../../pyproject", "../datasets", "/etc/passwd"):
        with pytest.raises((ScenarioNotFound, ValueError, OSError)):
            public_scenario(escape)


# -- events -------------------------------------------------------------------


def test_events_page_and_cursor_walk_the_whole_window(client: TestClient) -> None:
    expected = len(load_scenario(SCENARIOS_ROOT / SCENARIO).events)

    seen: list[str] = []
    cursor: str | None = None
    for _ in range(50):  # guard against a cursor that never advances
        url = f"/scenarios/{SCENARIO}/events?limit=25"
        if cursor:
            url += f"&cursor={cursor}"
        page = client.get(url).json()
        assert len(page["events"]) <= 25
        seen.extend(e["event_id"] for e in page["events"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    else:
        pytest.fail("cursor did not terminate")

    assert len(seen) == expected
    assert len(set(seen)) == expected, "keyset paging repeated an event"
    assert seen == sorted(seen), "events must come back in (ts, event_id) order"


def test_last_page_has_no_next_cursor(client: TestClient) -> None:
    page = client.get(f"/scenarios/{SCENARIO}/events?limit=500").json()
    assert page["next_cursor"] is None


def test_events_filter_by_pid(client: TestClient) -> None:
    scenario = load_scenario(SCENARIOS_ROOT / SCENARIO)
    pid = next(e.pid for e in scenario.events if e.pid is not None)
    page = client.get(f"/scenarios/{SCENARIO}/events?pid={pid}").json()
    assert page["events"]
    assert all(e["pid"] == pid for e in page["events"])


def test_events_filter_by_kind(client: TestClient) -> None:
    page = client.get(f"/scenarios/{SCENARIO}/events?kind=process_create").json()
    assert page["events"]
    assert all(e["kind"] == "process_create" for e in page["events"])


def test_events_free_text_search(client: TestClient) -> None:
    page = client.get(f"/scenarios/{SCENARIO}/events?q=powershell").json()
    assert page["events"]


def test_malformed_cursor_is_400_not_500(client: TestClient) -> None:
    resp = client.get(f"/scenarios/{SCENARIO}/events?cursor=not-base64!!")
    assert resp.status_code == 400
    assert "cursor" in resp.json()["detail"]


def test_cursor_without_separator_is_400(client: TestClient) -> None:
    import base64

    bad = base64.urlsafe_b64encode(b"no-separator-here").decode()
    assert client.get(f"/scenarios/{SCENARIO}/events?cursor={bad}").status_code == 400


def test_cursor_beyond_the_window_returns_an_empty_page(client: TestClient) -> None:
    far_future = encode_event_cursor("2999-01-01T00:00:00.000000Z", "ev-9999")
    page = client.get(f"/scenarios/{SCENARIO}/events?cursor={far_future}").json()
    assert page["events"] == []
    assert page["next_cursor"] is None


def test_limit_bounds_are_enforced(client: TestClient) -> None:
    assert client.get(f"/scenarios/{SCENARIO}/events?limit=0").status_code == 422
    assert client.get(f"/scenarios/{SCENARIO}/events?limit=501").status_code == 422


def test_events_for_unknown_scenario_is_404(client: TestClient) -> None:
    assert client.get("/scenarios/no_such_scenario/events").status_code == 404


# -- CORS ---------------------------------------------------------------------


def test_cors_allows_the_dev_server_origin(client: TestClient) -> None:
    resp = client.get("/scenarios", headers={"Origin": "http://localhost:5173"})
    assert resp.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_cors_does_not_echo_an_unknown_origin(client: TestClient) -> None:
    resp = client.get("/scenarios", headers={"Origin": "https://evil.example"})
    assert resp.headers.get("access-control-allow-origin") != "https://evil.example"
