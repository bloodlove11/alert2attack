"""Investigation job stores.

Two implementations behind one protocol:

- ``InMemoryJobStore`` — the default, and what every test uses. Behaviour is
  unchanged from the original store.
- ``SqliteJobStore`` — for the console, where a case URL should still open after
  the API restarts. Without it every link into a finished investigation 404s the
  moment the process dies.

Neither is a durable queue. A job that was *running* when the process died is
gone, because its work lived in that process. ``fail_stale_running`` marks those
failed on startup rather than leaving the console a spinner that never resolves
(design §6).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol

JobStatus = Literal["queued", "running", "succeeded", "failed"]


@dataclass
class InvestigationJob:
    id: str
    scenario_id: str
    model: str
    status: JobStatus = "queued"
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    error: str | None = None
    result: dict[str, Any] | None = None

    def touch(self) -> None:
        self.updated_at = datetime.now(UTC).isoformat()


class JobStore(Protocol):
    """What the API needs from a job store."""

    def create(self, *, scenario_id: str, model: str) -> InvestigationJob: ...

    def get(self, job_id: str) -> InvestigationJob | None: ...

    def update(self, job: InvestigationJob) -> None: ...

    def list(self, *, limit: int = 50) -> list[InvestigationJob]: ...


class InMemoryJobStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, InvestigationJob] = {}

    def create(self, *, scenario_id: str, model: str) -> InvestigationJob:
        job = InvestigationJob(id=str(uuid.uuid4()), scenario_id=scenario_id, model=model)
        with self._lock:
            self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> InvestigationJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def update(self, job: InvestigationJob) -> None:
        job.touch()
        with self._lock:
            self._jobs[job.id] = job

    def list(self, *, limit: int = 50) -> list[InvestigationJob]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)
            return jobs[:limit]


_JOBS_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
  id           TEXT PRIMARY KEY,
  scenario_id  TEXT NOT NULL,
  model        TEXT NOT NULL,
  status       TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL,
  error        TEXT,
  result_json  TEXT
);
CREATE INDEX IF NOT EXISTS ix_jobs_created ON jobs(created_at DESC);
"""


def _row_to_job(row: sqlite3.Row) -> InvestigationJob:
    return InvestigationJob(
        id=row["id"],
        scenario_id=row["scenario_id"],
        model=row["model"],
        status=row["status"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        error=row["error"],
        result=json.loads(row["result_json"]) if row["result_json"] else None,
    )


class SqliteJobStore:
    """Durable job records, so a case link survives a restart.

    ``check_same_thread=False`` plus an explicit lock: FastAPI runs sync endpoints
    and background tasks on a threadpool, so one connection is shared across
    threads. Writes are serialised by the lock rather than by sqlite's own
    threading mode, which keeps behaviour identical on every Python build.
    """

    def __init__(self, path: str | Path) -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # WAL so the console polling a job never blocks the run writing to it.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_JOBS_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def create(self, *, scenario_id: str, model: str) -> InvestigationJob:
        job = InvestigationJob(id=str(uuid.uuid4()), scenario_id=scenario_id, model=model)
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO jobs (id, scenario_id, model, status, created_at, updated_at,"
                " error, result_json) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)",
                (
                    job.id,
                    job.scenario_id,
                    job.model,
                    job.status,
                    job.created_at,
                    job.updated_at,
                ),
            )
        return job

    def get(self, job_id: str) -> InvestigationJob | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return None if row is None else _row_to_job(row)

    def update(self, job: InvestigationJob) -> None:
        job.touch()
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE jobs SET status = ?, updated_at = ?, error = ?, result_json = ? WHERE id = ?",
                (
                    job.status,
                    job.updated_at,
                    job.error,
                    json.dumps(job.result) if job.result is not None else None,
                    job.id,
                ),
            )

    def list(self, *, limit: int = 50) -> list[InvestigationJob]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_row_to_job(row) for row in rows]

    def fail_stale_running(self) -> int:
        """Mark jobs orphaned by a restart as failed. Returns how many.

        A queued or running job lived in a process that no longer exists, so
        nothing will ever finish it.
        """
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE jobs SET status = 'failed', error = ?, updated_at = ?"
                " WHERE status IN ('queued', 'running')",
                ("interrupted by an API restart", datetime.now(UTC).isoformat()),
            )
        return int(cur.rowcount)
