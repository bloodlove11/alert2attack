"""Analyst review of a case file.

The eval set is frozen and hand-built. An analyst disagreeing with a verdict
currently has nowhere to put that disagreement, so it never becomes a test
case. This is the smallest thing that closes that loop.

Two deliberate constraints:

- Append-only. A corrected verdict is an *observation about* a case file,
  never a mutation of one. A case file is the record of what the agent said on
  that run; editing it in place would destroy the only honest artifact here.
- Export, never a direct write. ``/reviews/export`` emits candidate eval
  cases for a human to curate. Writing them straight into the dev split would
  let the agent's own output quietly become its answer key, which is the same
  contamination the whole eval protocol exists to prevent.
"""

from __future__ import annotations

import sqlite3
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

Verdict = Literal["malicious", "suspicious", "likely_benign", "not_enough_evidence"]


class ReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agrees: bool
    corrected_verdict: Verdict | None = None
    note: str = Field(default="", max_length=2000)


class Review(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    job_id: str
    scenario_id: str
    agent_verdict: str
    agrees: bool
    corrected_verdict: Verdict | None
    note: str
    reviewer: str
    created_at: str


class EvalCaseCandidate(BaseModel):
    """What a curator would paste into a scenario manifest, not a gold label."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    agent_verdict: str
    proposed_verdict: Verdict
    note: str
    reviewer: str
    created_at: str
    source_job_id: str


class ReviewStore(Protocol):
    def add(self, review: Review) -> None: ...

    def list(self, *, scenario_id: str | None = None, limit: int = 100) -> list[Review]: ...


class InMemoryReviewStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._reviews: list[Review] = []

    def add(self, review: Review) -> None:
        with self._lock:
            self._reviews.append(review)

    def list(self, *, scenario_id: str | None = None, limit: int = 100) -> list[Review]:
        with self._lock:
            rows = list(self._reviews)
        if scenario_id is not None:
            rows = [r for r in rows if r.scenario_id == scenario_id]
        return sorted(rows, key=lambda r: r.created_at, reverse=True)[:limit]


_REVIEWS_SCHEMA = """
CREATE TABLE IF NOT EXISTS reviews (
  id                TEXT PRIMARY KEY,
  job_id            TEXT NOT NULL,
  scenario_id       TEXT NOT NULL,
  agent_verdict     TEXT NOT NULL,
  agrees            INTEGER NOT NULL,
  corrected_verdict TEXT,
  note              TEXT NOT NULL,
  reviewer          TEXT NOT NULL,
  created_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_reviews_scenario ON reviews(scenario_id);
CREATE INDEX IF NOT EXISTS ix_reviews_created ON reviews(created_at DESC);
"""


def _row_to_review(row: sqlite3.Row) -> Review:
    return Review(
        id=row["id"],
        job_id=row["job_id"],
        scenario_id=row["scenario_id"],
        agent_verdict=row["agent_verdict"],
        agrees=bool(row["agrees"]),
        corrected_verdict=row["corrected_verdict"],
        note=row["note"],
        reviewer=row["reviewer"],
        created_at=row["created_at"],
    )


class SqliteReviewStore:
    """Same threading posture as SqliteJobStore: one shared connection, our lock."""

    def __init__(self, path: str | Path) -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_REVIEWS_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def add(self, review: Review) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO reviews (id, job_id, scenario_id, agent_verdict, agrees,"
                " corrected_verdict, note, reviewer, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    review.id,
                    review.job_id,
                    review.scenario_id,
                    review.agent_verdict,
                    int(review.agrees),
                    review.corrected_verdict,
                    review.note,
                    review.reviewer,
                    review.created_at,
                ),
            )

    def list(self, *, scenario_id: str | None = None, limit: int = 100) -> list[Review]:
        sql = "SELECT * FROM reviews"
        params: list[Any] = []
        if scenario_id is not None:
            sql += " WHERE scenario_id = ?"
            params.append(scenario_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_review(row) for row in rows]


def build_review(
    *,
    job_id: str,
    scenario_id: str,
    agent_verdict: str,
    request: ReviewRequest,
    reviewer: str,
) -> Review:
    return Review(
        id=str(uuid.uuid4()),
        job_id=job_id,
        scenario_id=scenario_id,
        agent_verdict=agent_verdict,
        agrees=request.agrees,
        # A correction only means something when the reviewer disagreed.
        corrected_verdict=None if request.agrees else request.corrected_verdict,
        note=request.note,
        reviewer=reviewer,
        created_at=datetime.now(UTC).isoformat(),
    )


def export_candidates(reviews: list[Review]) -> list[EvalCaseCandidate]:
    """Only disagreements that name a verdict become candidates.

    An agreement teaches the eval set nothing it does not already encode, and a
    disagreement with no proposed verdict is not actionable.
    """
    return [
        EvalCaseCandidate(
            scenario_id=r.scenario_id,
            agent_verdict=r.agent_verdict,
            proposed_verdict=r.corrected_verdict,
            note=r.note,
            reviewer=r.reviewer,
            created_at=r.created_at,
            source_job_id=r.job_id,
        )
        for r in reviews
        if not r.agrees and r.corrected_verdict is not None
    ]
