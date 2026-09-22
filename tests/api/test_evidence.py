"""Evidence resolution: turn a citation back into what the agent fetched."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from alert2attack.api.app import create_app
from alert2attack.api.evidence import ledger_from_trace
from alert2attack.api.factory import ChatFactory
from alert2attack.domain.scenario import SCENARIOS_ROOT, load_scenario

SCENARIO = "otrf_empire_launcher_vbs"


@pytest.fixture
def finished_run(scripted_factory: ChatFactory) -> tuple[TestClient, dict[str, Any]]:
    client = TestClient(create_app(chat_factory=scripted_factory))
    resp = client.post(
        "/investigations",
        json={"scenario_id": SCENARIO, "model": "scripted", "sync": True},
    )
    assert resp.status_code == 200, resp.text
    return client, resp.json()


# -- ledger derivation --------------------------------------------------------


def test_ledger_ignores_failed_tool_calls() -> None:
    """A tool that failed showed the agent nothing, so it grants no citation."""
    trace = {
        "tool_calls": [
            {"seq": 1, "tool": "get_alert", "ok": True, "evidence_ids": ["ev-0001"]},
            {"seq": 2, "tool": "get_process", "ok": False, "evidence_ids": ["ev-0002"]},
            {"seq": 3, "tool": "search_events", "ok": True, "evidence_ids": ["ev-0001", "ev-0003"]},
        ]
    }
    assert ledger_from_trace(trace) == {"ev-0001": 1, "ev-0003": 3}


def test_ledger_records_first_sighting_not_last() -> None:
    trace = {
        "tool_calls": [
            {"seq": 4, "tool": "a", "ok": True, "evidence_ids": ["ev-0009"]},
            {"seq": 7, "tool": "b", "ok": True, "evidence_ids": ["ev-0009"]},
        ]
    }
    assert ledger_from_trace(trace)["ev-0009"] == 4


# -- resolution ---------------------------------------------------------------


def test_resolves_a_cited_event(finished_run: tuple[TestClient, dict[str, Any]]) -> None:
    client, job = finished_run
    cited = job["result"]["case_file"]["timeline"][0]["evidence"][0]

    resp = client.get(f"/investigations/{job['id']}/evidence/{cited}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["evidence_id"] == cited
    assert body["kind"] == "event"
    assert body["event"]["event_id"] == cited
    assert body["first_seen_tool_seq"] is not None
    assert body["rule"] is None and body["technique"] is None


def test_resolved_event_matches_the_source_telemetry(
    finished_run: tuple[TestClient, dict[str, Any]],
) -> None:
    client, job = finished_run
    cited = job["result"]["case_file"]["timeline"][0]["evidence"][0]
    body = client.get(f"/investigations/{job['id']}/evidence/{cited}").json()

    source = next(e for e in load_scenario(SCENARIOS_ROOT / SCENARIO).events if e.event_id == cited)
    assert body["event"]["kind"] == source.kind.value
    assert body["event"]["pid"] == source.pid


def test_every_citation_in_the_case_file_resolves(
    finished_run: tuple[TestClient, dict[str, Any]],
) -> None:
    """The verifier's promise, checked end to end over HTTP."""
    client, job = finished_run
    case_file = job["result"]["case_file"]

    cited: set[str] = set()
    for entry in case_file["timeline"]:
        cited.update(entry["evidence"])
    for technique in case_file["techniques"]:
        cited.update(technique["evidence"])
    for action in case_file["next_actions"]:
        cited.update(action["rationale"]["evidence"])

    assert cited, "fixture should cite something"
    for evidence_id in cited:
        resp = client.get(f"/investigations/{job['id']}/evidence/{evidence_id}")
        assert resp.status_code == 200, f"{evidence_id}: {resp.text}"


# -- failure modes ------------------------------------------------------------


def test_uncited_evidence_is_404(finished_run: tuple[TestClient, dict[str, Any]]) -> None:
    client, job = finished_run
    resp = client.get(f"/investigations/{job['id']}/evidence/ev-9999")
    assert resp.status_code == 404
    assert "ev-9999" in resp.json()["detail"]
    assert "never fetched" in resp.json()["detail"]


def test_malformed_evidence_id_is_422(finished_run: tuple[TestClient, dict[str, Any]]) -> None:
    client, job = finished_run
    resp = client.get(f"/investigations/{job['id']}/evidence/not-an-evidence-id")
    assert resp.status_code == 422


def test_unknown_job_is_404(finished_run: tuple[TestClient, dict[str, Any]]) -> None:
    client, _ = finished_run
    assert client.get("/investigations/no-such-job/evidence/ev-0001").status_code == 404


def test_evidence_response_carries_no_gold(
    finished_run: tuple[TestClient, dict[str, Any]],
) -> None:
    client, job = finished_run
    cited = job["result"]["case_file"]["timeline"][0]["evidence"][0]
    body = client.get(f"/investigations/{job['id']}/evidence/{cited}").text
    for marker in ("GOLD-MARKER", "key_pids", "acceptable_actions", "narrative"):
        assert marker not in body
