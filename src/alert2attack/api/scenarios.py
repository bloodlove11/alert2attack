"""Read-only scenario views for the console.

Every model here is built field by field from a manifest or from
``Scenario.public()``. Nothing in this module calls ``model_dump()`` on a
``Scenario``, because a ``Scenario`` carries ``gold`` — the held-out answer key —
and dumping one into an HTTP response would invalidate every published metric.

The boundary is enforced by ``tests/api/test_gold_boundary.py``.
"""

from __future__ import annotations

from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from alert2attack.domain.alert import Alert, Severity
from alert2attack.domain.events import Event
from alert2attack.domain.scenario import (
    SCENARIOS_ROOT,
    Scenario,
    iter_scenario_dirs,
    load_scenario,
    read_manifest,
)
from alert2attack.store.case_store import CaseStore

Split = Literal["dev", "test"]
Origin = Literal["otrf", "authored"]

# scenario_id doubles as a directory name, so it is validated against this before
# it reaches the filesystem. Mirrors the pattern on Scenario.scenario_id.
SCENARIO_ID_PATTERN = r"^[a-z0-9_]+$"


class ScenarioSummary(BaseModel):
    """One alert-queue row. Alert metadata only — never events, never gold."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    split: Split
    origin: Origin
    description: str = ""
    alert_id: str
    host: str
    rule_id: str
    rule_title: str
    severity: Severity
    fired_at: datetime


class ScenarioDetail(ScenarioSummary):
    """Queue row plus the boxed window. Still no events and still no gold."""

    model_config = ConfigDict(extra="forbid")

    window_start: datetime
    window_end: datetime
    trigger_event_id: str
    event_count: int


class EventPage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[Event]
    next_cursor: str | None = None
    limit: int


class ScenarioNotFound(KeyError):
    pass


def _summary_from_manifest(manifest: dict[str, Any]) -> ScenarioSummary:
    # Validating through Alert rather than reading raw keys keeps the timestamp
    # normalisation (and the UTC requirement) in one place.
    alert = Alert.model_validate(manifest["alert"])
    return ScenarioSummary(
        scenario_id=manifest["scenario_id"],
        split=manifest["split"],
        origin=manifest["origin"],
        description=manifest.get("description", ""),
        alert_id=alert.alert_id,
        host=alert.host,
        rule_id=alert.rule_id,
        rule_title=alert.rule_title,
        severity=alert.severity,
        fired_at=alert.fired_at,
    )


def list_summaries(root: Path = SCENARIOS_ROOT) -> list[ScenarioSummary]:
    """Queue rows for every committed scenario, newest alert first.

    Reads manifests only. A scenario whose manifest is unreadable or malformed is
    skipped rather than failing the whole queue — one bad directory should not
    take the console down.
    """
    summaries: list[ScenarioSummary] = []
    for scenario_dir in iter_scenario_dirs(root):
        try:
            summaries.append(_summary_from_manifest(read_manifest(scenario_dir)))
        except (OSError, ValueError, KeyError):
            continue
    return sorted(summaries, key=lambda s: (s.fired_at, s.scenario_id), reverse=True)


@lru_cache(maxsize=64)
def public_scenario(scenario_id: str, root: Path = SCENARIOS_ROOT) -> Scenario:
    """A gold-stripped scenario, cached.

    ``Scenario`` is frozen, so sharing one across request threads is safe. The
    ``.public()`` call is the single point where gold is dropped.
    """
    path = root / scenario_id
    if not (path / "manifest.yaml").is_file():
        raise ScenarioNotFound(scenario_id)
    return load_scenario(path).public()


def detail(scenario_id: str, root: Path = SCENARIOS_ROOT) -> ScenarioDetail:
    scenario = public_scenario(scenario_id, root)
    summary = _summary_from_manifest(read_manifest(root / scenario_id))
    return ScenarioDetail(
        **summary.model_dump(),
        window_start=scenario.window.start,
        window_end=scenario.window.end,
        trigger_event_id=scenario.alert.trigger_event_id,
        event_count=len(scenario.events),
    )


def case_store_for(scenario_id: str, root: Path = SCENARIOS_ROOT) -> CaseStore:
    """A fresh in-memory store for one request.

    Deliberately not cached. A ``sqlite3`` connection is bound to the thread that
    opened it, and FastAPI runs sync endpoints on a threadpool, so a shared store
    would need ``check_same_thread=False`` plus a lock. Loading ~200 events into
    memory costs single-digit milliseconds against the 200 ms budget, which is a
    better trade than adding cross-thread state to the store the agent also uses.
    """
    store = CaseStore()
    store.load_case(public_scenario(scenario_id, root))  # refuses gold at the door
    return store
