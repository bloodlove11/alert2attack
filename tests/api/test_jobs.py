"""Job stores: the in-memory default and the durable SQLite one."""

from __future__ import annotations

from pathlib import Path

import pytest

from alert2attack.api.app import create_app, default_job_store
from alert2attack.api.jobs import InMemoryJobStore, JobStore, SqliteJobStore


@pytest.fixture(params=["memory", "sqlite"])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> JobStore:
    """Both implementations must satisfy the same protocol."""
    if request.param == "memory":
        return InMemoryJobStore()
    return SqliteJobStore(tmp_path / "jobs.sqlite")


# -- shared contract ----------------------------------------------------------


def test_create_then_get_round_trips(store: JobStore) -> None:
    job = store.create(scenario_id="mini_001", model="scripted")
    got = store.get(job.id)
    assert got is not None
    assert (got.id, got.scenario_id, got.model, got.status) == (
        job.id,
        "mini_001",
        "scripted",
        "queued",
    )


def test_unknown_id_is_none(store: JobStore) -> None:
    assert store.get("no-such-job") is None


def test_update_persists_status_error_and_result(store: JobStore) -> None:
    job = store.create(scenario_id="mini_001", model="scripted")
    job.status = "succeeded"
    job.result = {"case_file": {"verdict": "malicious"}, "trace": {"tool_calls": []}}
    store.update(job)

    got = store.get(job.id)
    assert got is not None
    assert got.status == "succeeded"
    assert got.result is not None
    assert got.result["case_file"]["verdict"] == "malicious"
    assert got.error is None


def test_update_persists_failure(store: JobStore) -> None:
    job = store.create(scenario_id="mini_001", model="scripted")
    job.status = "failed"
    job.error = "ollama unreachable"
    store.update(job)

    got = store.get(job.id)
    assert got is not None
    assert got.status == "failed"
    assert got.error == "ollama unreachable"
    assert got.result is None


def test_update_bumps_updated_at(store: JobStore) -> None:
    job = store.create(scenario_id="mini_001", model="scripted")
    before = job.updated_at
    job.status = "running"
    store.update(job)
    got = store.get(job.id)
    assert got is not None
    assert got.updated_at >= before


def test_list_is_newest_first_and_respects_limit(store: JobStore) -> None:
    for i in range(5):
        store.create(scenario_id=f"scenario_{i}", model="scripted")

    listed = store.list(limit=3)
    assert len(listed) == 3
    assert [j.created_at for j in listed] == sorted(
        [j.created_at for j in listed], reverse=True
    )


def test_ids_are_unique(store: JobStore) -> None:
    ids = {store.create(scenario_id="mini_001", model="scripted").id for _ in range(20)}
    assert len(ids) == 20


# -- sqlite only --------------------------------------------------------------


def test_sqlite_survives_a_reopen(tmp_path: Path) -> None:
    """The reason this store exists: a case link must outlive the process."""
    db = tmp_path / "jobs.sqlite"
    first = SqliteJobStore(db)
    job = first.create(scenario_id="mini_001", model="scripted")
    job.status = "succeeded"
    job.result = {"case_file": {"verdict": "likely_benign"}}
    first.update(job)
    first.close()

    reopened = SqliteJobStore(db)
    got = reopened.get(job.id)
    assert got is not None
    assert got.status == "succeeded"
    assert got.result is not None
    assert got.result["case_file"]["verdict"] == "likely_benign"
    reopened.close()


def test_stale_running_jobs_are_failed_on_restart(tmp_path: Path) -> None:
    db = tmp_path / "jobs.sqlite"
    first = SqliteJobStore(db)

    running = first.create(scenario_id="a", model="scripted")
    running.status = "running"
    first.update(running)

    queued = first.create(scenario_id="b", model="scripted")  # left queued

    done = first.create(scenario_id="c", model="scripted")
    done.status = "succeeded"
    first.update(done)
    first.close()

    reopened = SqliteJobStore(db)
    assert reopened.fail_stale_running() == 2

    for job_id in (running.id, queued.id):
        got = reopened.get(job_id)
        assert got is not None
        assert got.status == "failed"
        assert got.error is not None
        assert "restart" in got.error

    finished = reopened.get(done.id)
    assert finished is not None
    assert finished.status == "succeeded", "a finished job must not be touched"
    reopened.close()


def test_default_store_is_in_memory_without_the_env_var(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ALERT2ATTACK_JOBS_DB", raising=False)
    assert isinstance(default_job_store(), InMemoryJobStore)


def test_default_store_is_sqlite_with_the_env_var(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    db = tmp_path / "jobs.sqlite"
    monkeypatch.setenv("ALERT2ATTACK_JOBS_DB", str(db))
    store_ = default_job_store()
    assert isinstance(store_, SqliteJobStore)
    assert db.exists()
    store_.close()


def test_app_uses_the_durable_store_when_configured(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("ALERT2ATTACK_JOBS_DB", str(tmp_path / "jobs.sqlite"))
    app = create_app()
    assert isinstance(app.state.job_store, SqliteJobStore)
    app.state.job_store.close()


def test_fail_stale_running_is_idempotent(tmp_path: Path) -> None:
    store_ = SqliteJobStore(tmp_path / "jobs.sqlite")
    job = store_.create(scenario_id="a", model="scripted")
    job.status = "running"
    store_.update(job)

    assert store_.fail_stale_running() == 1
    assert store_.fail_stale_running() == 0
    store_.close()
