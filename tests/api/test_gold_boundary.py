"""The gold boundary: no HTTP response may ever carry an answer key.

``Scenario.gold`` is the held-out answer (verdict, key_pids, acceptable actions,
narrative). ``CaseStore.load_case`` already refuses a scenario that still carries it
and the write prompt never sees it, but the console adds a *new* surface: routes that
serialise scenarios straight to a browser. A single naive ``model_dump()`` there would
ship the answer key to the client and make every published metric unciteable.

The assertions below are deliberately crude string matching over whole response bodies.
A typed check would only cover the fields someone remembered to type; this catches a
leak through a field nobody thought about.

Committed OTRF manifests carry ``narrative: GOLD-MARKER-OTRF...`` precisely so this
test has an unambiguous canary to search for.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from alert2attack.api.app import create_app
from alert2attack.domain.scenario import SCENARIOS_ROOT, load_scenario, peek_split

# A scenario whose manifest carries gold, so a leak would be visible.
GOLD_SCENARIO = "otrf_empire_launcher_vbs"

# Substrings that must never appear in a response body. Field names first, then the
# canary planted in every committed manifest.
GOLD_MARKERS = (
    "GOLD-MARKER",
    "acceptable_actions",
    "unacceptable_actions",
    "key_pids",
    "root_pid",
    "persistence_evidence",
    "narrative",
    '"gold"',
    "gold:",
)


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def _scenario_routes(scenario_id: str) -> list[str]:
    """Every read route that touches a scenario."""
    return [
        "/scenarios",
        "/scenarios?split=test",
        f"/scenarios/{scenario_id}",
        f"/scenarios/{scenario_id}/events",
        f"/scenarios/{scenario_id}/events?limit=200",
        f"/scenarios/{scenario_id}/events?q=powershell",
    ]


def _assert_clean(body: str, where: str) -> None:
    for marker in GOLD_MARKERS:
        assert marker not in body, f"{where} leaked gold marker {marker!r}"


def test_gold_is_present_in_the_source_manifest() -> None:
    """Guard the guard: if the fixture stops carrying gold, this suite proves nothing."""
    scenario = load_scenario(SCENARIOS_ROOT / GOLD_SCENARIO)
    assert scenario.gold is not None
    assert "GOLD-MARKER" in scenario.gold.narrative


def test_no_scenario_route_leaks_gold(client: TestClient) -> None:
    for path in _scenario_routes(GOLD_SCENARIO):
        resp = client.get(path)
        assert resp.status_code == 200, f"{path} -> {resp.status_code}: {resp.text[:200]}"
        _assert_clean(resp.text, path)


def test_every_committed_scenario_is_clean_over_http(client: TestClient) -> None:
    """Not just the one fixture — every scenario the queue can list."""
    listing = client.get("/scenarios")
    assert listing.status_code == 200
    _assert_clean(listing.text, "/scenarios")

    ids = [row["scenario_id"] for row in listing.json()]
    assert len(ids) >= 30, f"expected the full committed corpus, got {len(ids)}"

    for scenario_id in ids:
        detail = client.get(f"/scenarios/{scenario_id}")
        assert detail.status_code == 200, scenario_id
        _assert_clean(detail.text, f"/scenarios/{scenario_id}")


def test_openapi_schema_declares_no_gold_field(client: TestClient) -> None:
    """A response model with a gold field is a leak waiting for a code path."""
    schema = client.get("/openapi.json")
    assert schema.status_code == 200
    for name, component in schema.json()["components"]["schemas"].items():
        properties = component.get("properties", {})
        assert "gold" not in properties, f"schema {name} declares a gold field"


def test_investigation_result_carries_no_gold(client: TestClient) -> None:
    """The agent never sees gold, so its result must not echo one either."""
    resp = client.get("/investigations?limit=1")
    assert resp.status_code == 200
    _assert_clean(resp.text, "/investigations")


def test_split_is_exposed_but_gold_is_not(client: TestClient) -> None:
    """``split`` is metadata the queue needs; it is not an answer."""
    resp = client.get(f"/scenarios/{GOLD_SCENARIO}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["split"] == peek_split(SCENARIOS_ROOT / GOLD_SCENARIO)
    assert "gold" not in body
