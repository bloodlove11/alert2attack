import json
import warnings
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from alert2attack.domain.alert import Alert
from alert2attack.domain.events import Event, ensure_utc
from alert2attack.domain.evidence import EvidenceId

SCENARIOS_ROOT = Path(__file__).resolve().parents[3] / "datasets" / "scenarios"


def _read_utf8(path: Path) -> str:
    """Read a text file; tolerate Windows AV quirks on malware-like OTRF samples."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        # Some Windows/AV stacks reject text-mode open (Errno 22) but allow binary read.
        return path.read_bytes().decode("utf-8")


class Window(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    start: datetime
    end: datetime

    @field_validator("start", "end")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.end <= self.start:
            raise ValueError("window end must be after window start")
        return self

    def contains(self, ts: datetime) -> bool:
        return self.start <= ts <= self.end


class Gold(BaseModel):
    """Held-out answer. Read only by the evaluator, never by tools or the agent."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    verdict: Literal["malicious", "likely_benign", "not_enough_evidence"]
    techniques: list[str] = Field(default_factory=list)
    root_pid: int | None = None
    key_pids: list[int] = Field(default_factory=list)
    persistence_evidence: list[EvidenceId] = Field(default_factory=list)
    acceptable_actions: list[str] = Field(default_factory=list)
    unacceptable_actions: list[str] = Field(default_factory=list)
    narrative: str


class Provenance(BaseModel):
    """Where an OTRF-derived scenario came from (rebuild metadata)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    catalog_id: str | None = None
    source_url: str | None = None
    source_sha256: str | None = None


class Scenario(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str = Field(pattern=r"^[a-z0-9_]+$")
    split: Literal["dev", "test"]
    origin: Literal["otrf", "authored"]
    description: str = ""
    window: Window
    alert: Alert
    events: list[Event]
    gold: Gold | None = None
    provenance: Provenance | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        ids = [e.event_id for e in self.events]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate event_id in events")
        if self.alert.trigger_event_id not in ids:
            raise ValueError(f"alert.trigger_event_id {self.alert.trigger_event_id} is not in events")
        return self

    def public(self) -> "Scenario":
        """The view a tool or agent is allowed to see."""
        return self.model_copy(update={"gold": None})


def read_manifest(path: Path) -> dict[str, Any]:
    """Parse ``manifest.yaml`` without touching ``events.jsonl``.

    The console renders a queue of all 33 scenarios and needs only alert metadata,
    so it must not pay to parse and validate every event in every scenario.
    """
    manifest = yaml.safe_load(_read_utf8(path / "manifest.yaml"))
    if not isinstance(manifest, dict):
        raise ValueError(f"manifest at {path} is not a mapping")
    return manifest


def load_scenario(path: Path) -> Scenario:
    manifest = read_manifest(path)
    raw_events = [
        json.loads(line)
        for line in _read_utf8(path / "events.jsonl").splitlines()
        if line.strip()
    ]
    events = sorted((Event.model_validate(r) for r in raw_events), key=lambda e: e.ts)
    return Scenario.model_validate({**manifest, "events": events})


def iter_scenario_dirs(root: Path) -> Iterator[Path]:
    for manifest in sorted(root.glob("*/manifest.yaml")):
        yield manifest.parent


def peek_split(path: Path) -> str | None:
    """Read only ``split`` from manifest.yaml (no events)."""
    try:
        manifest = yaml.safe_load(_read_utf8(path / "manifest.yaml"))
    except OSError:
        return None
    if not isinstance(manifest, dict):
        return None
    split = manifest.get("split")
    return split if isinstance(split, str) else None


def iter_scenarios(root: Path, *, skip_unreadable: bool = True) -> Iterator[Scenario]:
    for scenario_dir in iter_scenario_dirs(root):
        try:
            yield load_scenario(scenario_dir)
        except OSError as exc:
            if not skip_unreadable:
                raise
            warnings.warn(
                f"skipping unreadable scenario {scenario_dir.name}: {exc}",
                stacklevel=2,
            )
