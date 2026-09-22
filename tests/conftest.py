from pathlib import Path

import pytest

from alert2attack.domain.scenario import Scenario, load_scenario

# Synthetic fixture for unit tests only — committed datasets under datasets/scenarios are OTRF-only.
DOWNLOADER = Path(__file__).resolve().parent / "fixtures" / "scenarios" / "enc_ps_downloader_001"


@pytest.fixture
def downloader_scenario() -> Scenario:
    return load_scenario(DOWNLOADER)


@pytest.fixture
def scenario_dir(tmp_path: Path) -> Path:
    """A minimal valid scenario directory the tests can mutate."""
    d = tmp_path / "mini_001"
    d.mkdir()
    (d / "manifest.yaml").write_text(
        """
scenario_id: mini_001
split: dev
origin: authored
description: minimal
window:
  start: 2024-01-01T00:00:00Z
  end: 2024-01-01T01:00:00Z
alert:
  alert_id: alr-mini
  host: HOST-A
  fired_at: 2024-01-01T00:10:00Z
  rule_id: win_powershell_encoded_command
  rule_title: Suspicious Encoded PowerShell Command Line
  severity: medium
  trigger_event_id: ev-0002
gold:
  verdict: not_enough_evidence
  techniques: []
  root_pid: 10
  key_pids: [10, 20]
  acceptable_actions: [collect_script]
  narrative: GOLD-MARKER-MINI
"""
    )
    (d / "events.jsonl").write_text(
        "\n".join(
            [
                '{"event_id":"ev-0001","kind":"process_create","ts":"2024-01-01T00:09:00Z",'
                '"host":"HOST-A","pid":10,"ppid":1,"image":"C:\\\\Windows\\\\System32\\\\cmd.exe"}',
                '{"event_id":"ev-0002","kind":"process_create","ts":"2024-01-01T00:10:00Z",'
                '"host":"HOST-A","pid":20,"ppid":10,"image":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell'
                '\\\\v1.0\\\\powershell.exe","command_line":"powershell -enc QQBCAA=="}',
                '{"event_id":"ev-0003","kind":"process_create","ts":"2024-01-01T02:00:00Z",'
                '"host":"HOST-A","pid":30,"ppid":10,"image":"C:\\\\late.exe"}',
                '{"event_id":"ev-0004","kind":"process_create","ts":"2024-01-01T00:11:00Z",'
                '"host":"HOST-B","pid":40,"ppid":10,"image":"C:\\\\otherhost.exe"}',
            ]
        )
        + "\n"
    )
    return d
