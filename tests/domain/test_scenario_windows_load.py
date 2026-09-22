"""Windows-safe scenario loading: peek split before events; skip unreadable."""

from __future__ import annotations

from pathlib import Path

import pytest

from alert2attack.domain.scenario import _read_utf8, iter_scenarios, peek_split
from alert2attack.eval.runner import _scenarios


def test_peek_split_reads_manifest_only(tmp_path: Path) -> None:
    d = tmp_path / "s1"
    d.mkdir()
    (d / "manifest.yaml").write_text("scenario_id: s1\nsplit: test\norigin: authored\n", encoding="utf-8")
    assert peek_split(d) == "test"
    assert peek_split(tmp_path / "missing") is None


def test_scenarios_skips_other_splits_without_opening_their_events(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "scenarios"
    good = root / "good_test"
    blocked = root / "blocked_dev"
    good.mkdir(parents=True)
    blocked.mkdir(parents=True)

    # Minimal valid scenario files for good_test
    (good / "manifest.yaml").write_text(
        """
scenario_id: good_test
split: test
origin: authored
description: ok
window:
  start: 2020-01-01T00:00:00Z
  end: 2020-01-01T01:00:00Z
alert:
  alert_id: a1
  host: HOST
  fired_at: 2020-01-01T00:30:00Z
  rule_id: r
  rule_title: t
  severity: low
  trigger_event_id: ev-0001
gold:
  verdict: malicious
  techniques: []
  narrative: GOLD
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (good / "events.jsonl").write_text(
        '{"event_id":"ev-0001","kind":"process_create","ts":"2020-01-01T00:30:00Z",'
        '"host":"HOST","pid":1,"ppid":0,"image":"C:\\\\a.exe"}\n',
        encoding="utf-8",
    )

    (blocked / "manifest.yaml").write_text(
        "scenario_id: blocked_dev\nsplit: dev\norigin: otrf\n",
        encoding="utf-8",
    )
    (blocked / "events.jsonl").write_text("SHOULD_NOT_OPEN\n", encoding="utf-8")

    real_read_bytes = Path.read_bytes

    def guarded_bytes(self: Path) -> bytes:
        if self.parent.name == "blocked_dev" and self.name == "events.jsonl":
            raise OSError(22, "Invalid argument", str(self))
        return real_read_bytes(self)

    real_read_text = Path.read_text

    def guarded_text(self: Path, *args: object, **kwargs: object) -> str:
        if self.parent.name == "blocked_dev" and self.name == "events.jsonl":
            raise OSError(22, "Invalid argument", str(self))
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", guarded_bytes)
    monkeypatch.setattr(Path, "read_text", guarded_text)

    out = _scenarios(root, "test", limit=None)
    assert len(out) == 1
    assert out[0].scenario_id == "good_test"


def test_read_utf8_falls_back_to_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "f.txt"
    path.write_text("hello", encoding="utf-8")
    real_read_text = Path.read_text

    def fail_text(self: Path, *args: object, **kwargs: object) -> str:
        if self == path:
            raise OSError(22, "Invalid argument", str(self))
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fail_text)
    assert _read_utf8(path) == "hello"


def test_iter_scenarios_skips_unreadable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    d = tmp_path / "blocked"
    d.mkdir()
    (d / "manifest.yaml").write_text(
        """
scenario_id: blocked
split: test
origin: authored
description: x
window:
  start: 2020-01-01T00:00:00Z
  end: 2020-01-01T01:00:00Z
alert:
  alert_id: a
  host: h
  fired_at: 2020-01-01T00:30:00Z
  rule_id: r
  rule_title: t
  severity: low
  trigger_event_id: ev-0001
gold:
  verdict: malicious
  techniques: []
  narrative: GOLD
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (d / "events.jsonl").write_text(
        '{"event_id":"ev-0001","kind":"process_create","ts":"2020-01-01T00:30:00Z",'
        '"host":"h","pid":1,"ppid":0,"image":"C:\\\\a.exe"}\n',
        encoding="utf-8",
    )

    real_read_text = Path.read_text
    real_read_bytes = Path.read_bytes

    def fail_events_text(self: Path, *args: object, **kwargs: object) -> str:
        if self.name == "events.jsonl":
            raise OSError(22, "Invalid argument", str(self))
        return real_read_text(self, *args, **kwargs)

    def fail_events_bytes(self: Path) -> bytes:
        if self.name == "events.jsonl":
            raise OSError(22, "Invalid argument", str(self))
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_text", fail_events_text)
    monkeypatch.setattr(Path, "read_bytes", fail_events_bytes)

    with pytest.warns(UserWarning, match="skipping unreadable"):
        assert list(iter_scenarios(tmp_path)) == []
