"""Analyst review: the loop from a disagreement to a candidate eval case."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from alert2attack.api.app import create_app
from alert2attack.api.factory import ChatFactory
from alert2attack.api.reviews import (
    InMemoryReviewStore,
    Review,
    ReviewRequest,
    ReviewStore,
    SqliteReviewStore,
    build_review,
    export_candidates,
)

SCENARIO = "otrf_empire_launcher_vbs"


def _review(**overrides: Any) -> Review:
    base: dict[str, Any] = {
        "job_id": "job-1",
        "scenario_id": SCENARIO,
        "agent_verdict": "malicious",
        "request": ReviewRequest(agrees=False, corrected_verdict="likely_benign", note="backup tool"),
        "reviewer": "analyst",
    }
    base.update(overrides)
    return build_review(**base)


# -- the store contract -------------------------------------------------------


@pytest.fixture(params=["memory", "sqlite"])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> ReviewStore:
    if request.param == "memory":
        return InMemoryReviewStore()
    return SqliteReviewStore(tmp_path / "reviews.sqlite")


def test_add_then_list(store: ReviewStore) -> None:
    review = _review()
    store.add(review)
    listed = store.list()
    assert len(listed) == 1
    assert listed[0].id == review.id
    assert listed[0].corrected_verdict == "likely_benign"
    assert listed[0].note == "backup tool"


def test_list_filters_by_scenario(store: ReviewStore) -> None:
    store.add(_review())
    store.add(_review(scenario_id="other_scenario"))
    assert len(store.list(scenario_id=SCENARIO)) == 1
    assert len(store.list()) == 2


def test_list_is_newest_first_and_limited(store: ReviewStore) -> None:
    for _ in range(5):
        store.add(_review())
    listed = store.list(limit=3)
    assert len(listed) == 3
    assert [r.created_at for r in listed] == sorted([r.created_at for r in listed], reverse=True)


def test_sqlite_reviews_survive_a_reopen(tmp_path: Path) -> None:
    db = tmp_path / "reviews.sqlite"
    first = SqliteReviewStore(db)
    review = _review()
    first.add(review)
    first.close()

    reopened = SqliteReviewStore(db)
    assert [r.id for r in reopened.list()] == [review.id]
    reopened.close()


# -- building -----------------------------------------------------------------


def test_agreement_drops_any_corrected_verdict() -> None:
    """A correction only means something when the reviewer disagreed."""
    review = build_review(
        job_id="j",
        scenario_id=SCENARIO,
        agent_verdict="malicious",
        request=ReviewRequest(agrees=True, corrected_verdict="likely_benign"),
        reviewer="analyst",
    )
    assert review.corrected_verdict is None


# -- export -------------------------------------------------------------------


def test_only_actionable_disagreements_are_exported() -> None:
    reviews = [
        _review(request=ReviewRequest(agrees=True, note="looks right")),
        _review(request=ReviewRequest(agrees=False, note="wrong but I am not sure what")),
        _review(request=ReviewRequest(agrees=False, corrected_verdict="likely_benign", note="backup")),
    ]
    candidates = export_candidates(reviews)
    assert len(candidates) == 1
    assert candidates[0].proposed_verdict == "likely_benign"
    assert candidates[0].agent_verdict == "malicious"


def test_export_is_a_proposal_not_a_gold_label() -> None:
    """The field names must not read like an answer key."""
    candidate = export_candidates([_review()])[0]
    dumped = candidate.model_dump()
    assert "proposed_verdict" in dumped
    assert "gold" not in dumped
    assert "verdict" not in dumped, "a bare 'verdict' would invite pasting it in as truth"


# -- the routes ---------------------------------------------------------------


@pytest.fixture
def finished(scripted_factory: ChatFactory) -> tuple[TestClient, dict[str, Any]]:
    client = TestClient(create_app(chat_factory=scripted_factory))
    job = client.post(
        "/investigations",
        json={"scenario_id": SCENARIO, "model": "scripted", "sync": True},
    ).json()
    assert job["status"] == "succeeded"
    return client, job


def test_posting_a_review_records_the_agent_verdict(
    finished: tuple[TestClient, dict[str, Any]],
) -> None:
    client, job = finished
    resp = client.post(
        f"/investigations/{job['id']}/review",
        json={"agrees": False, "corrected_verdict": "likely_benign", "note": "backup product"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["agent_verdict"] == job["result"]["case_file"]["verdict"]
    assert body["corrected_verdict"] == "likely_benign"
    assert body["scenario_id"] == SCENARIO


def test_a_review_never_mutates_the_case_file(
    finished: tuple[TestClient, dict[str, Any]],
) -> None:
    """A review is an observation about a run, not an edit to it."""
    client, job = finished
    before = client.get(f"/investigations/{job['id']}").json()["result"]["case_file"]
    client.post(
        f"/investigations/{job['id']}/review",
        json={"agrees": False, "corrected_verdict": "not_enough_evidence"},
    )
    after = client.get(f"/investigations/{job['id']}").json()["result"]["case_file"]
    assert before == after


def test_disagreement_without_a_verdict_is_422(
    finished: tuple[TestClient, dict[str, Any]],
) -> None:
    client, job = finished
    resp = client.post(f"/investigations/{job['id']}/review", json={"agrees": False})
    assert resp.status_code == 422
    assert "actionable" in resp.json()["detail"]


def test_agreement_needs_no_verdict(finished: tuple[TestClient, dict[str, Any]]) -> None:
    client, job = finished
    assert client.post(f"/investigations/{job['id']}/review", json={"agrees": True}).status_code == 201


def test_review_on_an_unknown_job_is_404(finished: tuple[TestClient, dict[str, Any]]) -> None:
    client, _ = finished
    resp = client.post("/investigations/nope/review", json={"agrees": True})
    assert resp.status_code == 404


def test_reviews_are_listed_and_filtered(finished: tuple[TestClient, dict[str, Any]]) -> None:
    client, job = finished
    client.post(f"/investigations/{job['id']}/review", json={"agrees": True})
    assert len(client.get("/reviews").json()) == 1
    assert len(client.get(f"/reviews?scenario_id={SCENARIO}").json()) == 1
    assert client.get("/reviews?scenario_id=nothing_here").json() == []


def test_export_route_returns_curation_candidates(
    finished: tuple[TestClient, dict[str, Any]],
) -> None:
    client, job = finished
    client.post(f"/investigations/{job['id']}/review", json={"agrees": True})
    client.post(
        f"/investigations/{job['id']}/review",
        json={"agrees": False, "corrected_verdict": "suspicious", "note": "over-called"},
    )
    candidates = client.get("/reviews/export").json()
    assert len(candidates) == 1
    assert candidates[0]["proposed_verdict"] == "suspicious"
    assert candidates[0]["source_job_id"] == job["id"]


def test_review_responses_carry_no_gold(finished: tuple[TestClient, dict[str, Any]]) -> None:
    client, job = finished
    client.post(f"/investigations/{job['id']}/review", json={"agrees": True})
    for path in ("/reviews", "/reviews/export"):
        body = client.get(path).text
        for marker in ("GOLD-MARKER", "key_pids", "acceptable_actions", "narrative"):
            assert marker not in body
