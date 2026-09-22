import json
from pathlib import Path

from alert2attack.dataset.build import build_scenario_from_records, write_scenario_dir
from alert2attack.dataset.catalog import CatalogEntry, load_catalog
from alert2attack.domain.scenario import Provenance, load_scenario

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "otrf" / "sample_sysmon.jsonl"


def test_build_scenario_from_fixture(tmp_path: Path) -> None:
    records = [json.loads(line) for line in FIXTURE.read_text().splitlines() if line.strip()]
    scenario = build_scenario_from_records(
        records,
        scenario_id="otrf_empire_vbs_001",
        techniques=["T1059.001", "T1027"],
        preferred_host_substring="WORKSTATION5",
        provenance=Provenance(
            catalog_id="empire_launcher_vbs",
            source_url="https://example.test/empire.zip",
            source_sha256="a" * 64,
        ),
        gold_narrative="GOLD-MARKER-OTRF. Empire VBS launcher encoded PowerShell on WORKSTATION5.",
    )
    assert scenario.origin == "otrf"
    assert scenario.gold is not None and scenario.gold.verdict == "malicious"
    assert scenario.provenance is not None and scenario.provenance.catalog_id == "empire_launcher_vbs"
    assert any(e.kind.value == "process_create" for e in scenario.events)
    out = write_scenario_dir(scenario, tmp_path / scenario.scenario_id)
    reloaded = load_scenario(out)
    assert reloaded.scenario_id == scenario.scenario_id
    assert reloaded.gold is not None and "GOLD-MARKER" in reloaded.gold.narrative


def test_load_catalog(tmp_path: Path) -> None:
    path = tmp_path / "catalog.yaml"
    path.write_text(
        """
datasets:
  - id: empire_launcher_vbs
    url: https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/execution/host/empire_launcher_vbs.zip
    sha256: "876430f905878589738d79dd434bd128dda50054aaaaaaaaaaaaaaaaaaaaaaaa"
    techniques: [T1059.001]
    preferred_host_substring: WORKSTATION5
    notes: empire vbs launcher
"""
    )
    # sha must be 64 hex — fix
    path.write_text(
        """
datasets:
  - id: empire_launcher_vbs
    url: https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/execution/host/empire_launcher_vbs.zip
    sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    techniques: [T1059.001]
    preferred_host_substring: WORKSTATION5
"""
    )
    entries = load_catalog(path)
    assert len(entries) == 1
    assert isinstance(entries[0], CatalogEntry)
    assert entries[0].id == "empire_launcher_vbs"
