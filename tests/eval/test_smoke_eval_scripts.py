"""Tests for eval smoke / report table helpers."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from alert2attack.eval.runner import run_eval

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_smoke_scripted_factory_runs_one_case(tmp_path: Path) -> None:
    smoke = _load("smoke_eval.py")
    report = run_eval(
        arm="agent-scripted",
        split="test",
        out_dir=tmp_path / "reports",
        limit=1,
        scripted_factory=smoke._scripted_factory,
    )
    assert report.n == 1
    assert report.mean_citation_post == 1.0
    assert list((tmp_path / "reports").glob("*-agent-scripted-test.json"))


def test_render_eval_table_picks_newest_and_unwraps(tmp_path: Path) -> None:
    render_mod = _load("render_eval_table.py")
    older = tmp_path / "2026-01-01-agent-local-7b-test.json"
    newer = tmp_path / "2026-09-09-agent-local-7b-test.json"
    payload = {
        "arm": "agent-local-7b",
        "split": "test",
        "n": 2,
        "verdict_accuracy": 0.1,
        "mean_verdict_cost": 3.0,
        "mean_citation_validity_post": 0.2,
        "mean_key_pid_recall": 0.3,
        "action_safety_rate": 1.0,
    }
    older.write_text(json.dumps({"report": payload}), encoding="utf-8")
    payload2 = {**payload, "verdict_accuracy": 0.9}
    newer.write_text(json.dumps({"report": payload2}), encoding="utf-8")

    rows = render_mod._newest_per_arm_split(render_mod._load_reports(tmp_path))
    assert len(rows) == 1
    assert rows[0]["verdict_accuracy"] == 0.9
    table = render_mod.render(rows)
    assert "`agent-local-7b`" in table
    assert "0.90" in table
    assert "no reports yet" in render_mod.render([])
