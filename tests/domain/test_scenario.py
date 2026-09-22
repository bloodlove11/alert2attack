from pathlib import Path

import pytest
from pydantic import ValidationError

from alert2attack.domain.scenario import SCENARIOS_ROOT, Scenario, iter_scenarios, load_scenario


def test_loads_fixture_downloader(downloader_scenario: Scenario) -> None:
    s = downloader_scenario
    assert s.scenario_id == "enc_ps_downloader_001"
    assert len(s.events) == 12
    assert s.alert.trigger_event_id == "ev-0004"
    assert s.gold is not None and s.gold.verdict == "malicious"
    assert s.events == sorted(s.events, key=lambda e: e.ts)


def test_public_strips_gold(downloader_scenario: Scenario) -> None:
    pub = downloader_scenario.public()
    assert pub.gold is None
    assert pub.events == downloader_scenario.events
    assert downloader_scenario.gold is not None  # original untouched


def test_trigger_event_must_exist(scenario_dir: Path) -> None:
    manifest = scenario_dir / "manifest.yaml"
    manifest.write_text(manifest.read_text().replace("trigger_event_id: ev-0002", "trigger_event_id: ev-0099"))
    with pytest.raises(ValidationError, match="trigger_event_id"):
        load_scenario(scenario_dir)


def test_duplicate_event_ids_rejected(scenario_dir: Path) -> None:
    events = scenario_dir / "events.jsonl"
    lines = events.read_text().splitlines()
    events.write_text("\n".join(lines + [lines[0]]) + "\n")
    with pytest.raises(ValidationError, match="duplicate"):
        load_scenario(scenario_dir)


def test_window_end_after_start(scenario_dir: Path) -> None:
    manifest = scenario_dir / "manifest.yaml"
    manifest.write_text(manifest.read_text().replace("end: 2024-01-01T01:00:00Z", "end: 2023-12-31T23:00:00Z"))
    with pytest.raises(ValidationError, match="window"):
        load_scenario(scenario_dir)


def test_iter_scenarios_finds_every_committed_scenario() -> None:
    ids = sorted(s.scenario_id for s in iter_scenarios(SCENARIOS_ROOT))
    assert any(i.startswith("otrf_") for i in ids)
    assert "enc_ps_downloader_001" not in ids  # synthetic fixture is not a committed dataset
    assert ids == sorted(set(ids))
