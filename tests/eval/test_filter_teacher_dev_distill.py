"""DR-012 teacher-dev distill filter (draft; not a training job)."""

from __future__ import annotations

import importlib.util
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "distill" / "teacher-dev-filter-sample.jsonl"

KEEP_IDS = (
    "keep_passed_empty_messages",
    "keep_degraded_verdict_match",
    "keep_passed_exhausted_verdict_match",
    "keep_repaired_with_messages",
    "keep_repaired_exhausted_verdict_match",
)


def _load_filter():
    path = ROOT / "scripts" / "filter_teacher_dev_distill.py"
    spec = importlib.util.spec_from_file_location("filter_teacher_dev_distill", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _rows(path: Path = FIXTURE) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _by_id(scenario_id: str) -> dict[str, Any]:
    return deepcopy(next(r for r in _rows() if r["scenario_id"] == scenario_id))


def _clone(row: dict[str, Any], **fields: Any) -> dict[str, Any]:
    out = deepcopy(row)
    out.update(fields)
    return out


def test_fixture_covers_dr012_keep_and_drop_cases() -> None:
    ids = {str(r["scenario_id"]) for r in _rows()}
    for required in (
        *KEEP_IDS,
        "drop_failed_verify",
        "drop_citation_low",
        "drop_test_split",
        "drop_verdict_mismatch",
        "drop_passed_exhausted_verdict_mismatch",
        "drop_degraded_verdict_mismatch",
    ):
        assert required in ids
    empty = _by_id("keep_passed_empty_messages")
    assert empty["messages"] == []
    exhausted = _by_id("keep_passed_exhausted_verdict_match")
    assert exhausted["trace"]["budget"]["tool_exhausted"] is True
    mismatch_exhausted = _by_id("drop_passed_exhausted_verdict_mismatch")
    assert mismatch_exhausted["trace"]["budget"]["tool_exhausted"] is True
    assert mismatch_exhausted["case_file"]["verdict"] != mismatch_exhausted["gold_verdict"]


def test_filter_keeps_dr012_rows_and_reports_drop_reasons() -> None:
    mod = _load_filter()
    kept, summary = mod.filter_records(_rows(), prefer_correct_verdict=True)
    assert [r["scenario_id"] for r in kept] == list(KEEP_IDS)
    dropped = summary["dropped_by_reason"]
    assert dropped["bad_verification"] == 1  # failed
    assert dropped.get("budget_exhausted", 0) == 0
    assert dropped["citation_below_threshold"] == 1
    assert dropped["not_dev_split"] == 1
    assert dropped["verdict_mismatch"] == 2  # repaired mismatch + passed exhausted mal→NEE
    assert dropped["degraded_no_verdict_match"] == 1
    assert summary["degraded_kept"] == 1
    assert summary["n_in"] == 11
    assert summary["n_kept"] == 5
    assert summary["any_nonempty_messages"] is True
    assert summary["n_kept_with_nonempty_messages"] == 1
    assert summary["ready"] is True
    assert summary["filter_revision"] == "DR-012"
    assert summary["kill_filtered_n_lt_8"] is True
    assert summary["kill_filtered_n_lt_12"] is True
    assert summary["smoke_sft_discuss_clears"] is False
    assert summary["full_lora_n_ok"] is False


def test_passed_exhausted_kept_when_verdict_matches() -> None:
    mod = _load_filter()
    row = _by_id("keep_passed_exhausted_verdict_match")
    kept, summary = mod.filter_records([row], prefer_correct_verdict=True)
    assert [r["scenario_id"] for r in kept] == ["keep_passed_exhausted_verdict_match"]
    assert summary["dropped_by_reason"].get("budget_exhausted", 0) == 0


def test_passed_exhausted_dropped_by_prefer_correct() -> None:
    mod = _load_filter()
    row = _by_id("drop_passed_exhausted_verdict_mismatch")
    kept_on, summary_on = mod.filter_records([row], prefer_correct_verdict=True)
    kept_off, _ = mod.filter_records([row], prefer_correct_verdict=False)
    assert kept_on == []
    assert summary_on["dropped_by_reason"]["verdict_mismatch"] == 1
    assert summary_on["dropped_by_reason"].get("budget_exhausted", 0) == 0
    assert [r["scenario_id"] for r in kept_off] == ["drop_passed_exhausted_verdict_mismatch"]


def test_degraded_verdict_match_kept() -> None:
    mod = _load_filter()
    row = _by_id("keep_degraded_verdict_match")
    kept, summary = mod.filter_records([row], prefer_correct_verdict=True)
    assert [r["scenario_id"] for r in kept] == ["keep_degraded_verdict_match"]
    assert summary["degraded_kept"] == 1
    assert summary["dropped_by_reason"]["degraded_no_verdict_match"] == 0


def test_degraded_mismatch_dropped() -> None:
    mod = _load_filter()
    row = _by_id("drop_degraded_verdict_mismatch")
    kept_on, summary_on = mod.filter_records([row], prefer_correct_verdict=True)
    kept_off, summary_off = mod.filter_records([row], prefer_correct_verdict=False)
    assert kept_on == []
    assert kept_off == []
    assert summary_on["dropped_by_reason"]["degraded_no_verdict_match"] == 1
    assert summary_off["dropped_by_reason"]["degraded_no_verdict_match"] == 1
    assert summary_on["degraded_kept"] == 0


def test_repaired_path_kept_including_exhausted() -> None:
    mod = _load_filter()
    rows = [_by_id("keep_repaired_with_messages"), _by_id("keep_repaired_exhausted_verdict_match")]
    kept, _ = mod.filter_records(rows, prefer_correct_verdict=True)
    assert [r["scenario_id"] for r in kept] == [
        "keep_repaired_with_messages",
        "keep_repaired_exhausted_verdict_match",
    ]


def test_citation_below_threshold_dropped() -> None:
    mod = _load_filter()
    row = _by_id("drop_citation_low")
    kept, summary = mod.filter_records([row], prefer_correct_verdict=True)
    assert kept == []
    assert summary["dropped_by_reason"]["citation_below_threshold"] == 1


def test_filter_drops_test_split_even_when_messages_present() -> None:
    mod = _load_filter()
    test_row = _by_id("drop_test_split")
    kept, summary = mod.filter_records([test_row], prefer_correct_verdict=True)
    assert kept == []
    assert summary["dropped_by_reason"]["not_dev_split"] == 1
    assert summary["ready"] is False


def test_prefer_correct_verdict_default_on_and_can_be_disabled() -> None:
    mod = _load_filter()
    mismatch = _by_id("drop_verdict_mismatch")
    kept_default, summary_default = mod.filter_records([mismatch])
    kept_on, _ = mod.filter_records([mismatch], prefer_correct_verdict=True)
    kept_off, _ = mod.filter_records([mismatch], prefer_correct_verdict=False)
    assert kept_default == []
    assert kept_on == []
    assert summary_default["prefer_correct_verdict"] is True
    assert [r["scenario_id"] for r in kept_off] == ["drop_verdict_mismatch"]


def test_explicit_citation_validity_post_is_used_when_present() -> None:
    mod = _load_filter()
    row = _by_id("keep_passed_empty_messages")
    enriched = dict(row)
    enriched["citation_validity_post"] = 0.5
    kept, summary = mod.filter_records([enriched], prefer_correct_verdict=True)
    assert kept == []
    assert summary["dropped_by_reason"]["citation_below_threshold"] == 1


def test_recomputed_citation_matches_metrics_formula() -> None:
    """distill_record has no citation_post; filter recomputes from case_file vs ledger."""
    from alert2attack.domain.casefile import CaseFile
    from alert2attack.eval.metrics import citation_validity

    mod = _load_filter()
    row = _by_id("drop_citation_low")
    cf = CaseFile.model_validate(row["case_file"])
    ledger = {eid for c in row["trace"]["tool_calls"] for eid in c["evidence_ids"]}
    assert citation_validity(cf, ledger) == 0.5
    assert mod.citation_post(row) == pytest.approx(0.5)
    kept, _ = mod.filter_records([row], prefer_correct_verdict=True)
    assert kept == []


def test_n20_teacher_dev_shape_under_dr012_prefer_correct() -> None:
    """PLUMB-DISTILL teacher-dev: 16 degraded (9 match) + 4 passed+exhausted mal→NEE → N=9."""
    mod = _load_filter()
    seed = _by_id("keep_degraded_verdict_match")
    rows: list[dict[str, Any]] = []
    for i in range(9):
        rows.append(_clone(seed, scenario_id=f"degraded_match_{i}"))
    mismatch_degraded = _by_id("drop_degraded_verdict_mismatch")
    for i in range(7):
        rows.append(_clone(mismatch_degraded, scenario_id=f"degraded_mismatch_{i}"))
    exhausted_mismatch = _by_id("drop_passed_exhausted_verdict_mismatch")
    for i in range(4):
        rows.append(_clone(exhausted_mismatch, scenario_id=f"passed_exhausted_nee_{i}"))
    kept, summary = mod.filter_records(rows, prefer_correct_verdict=True)
    assert summary["n_in"] == 20
    assert summary["n_kept"] == 9
    assert summary["degraded_kept"] == 9
    assert summary["dropped_by_reason"]["degraded_no_verdict_match"] == 7
    assert summary["dropped_by_reason"]["verdict_mismatch"] == 4
    assert summary["dropped_by_reason"].get("budget_exhausted", 0) == 0
    assert summary["kill_filtered_n_lt_8"] is False
    assert summary["kill_filtered_n_lt_12"] is True
    assert summary["smoke_sft_discuss_clears"] is True
    assert summary["full_lora_n_ok"] is False
    assert [r["scenario_id"] for r in kept] == [f"degraded_match_{i}" for i in range(9)]


def test_all_empty_messages_is_not_ready_and_cli_exits_nonzero(tmp_path: Path) -> None:
    mod = _load_filter()
    row = _by_id("keep_passed_empty_messages")
    src = tmp_path / "teacher-dev.jsonl"
    src.write_text(json.dumps(row) + "\n", encoding="utf-8")
    out = tmp_path / "filtered.jsonl"
    summary_path = tmp_path / "summary.json"
    code = mod.main(
        [
            str(src),
            "--out",
            str(out),
            "--summary",
            str(summary_path),
        ]
    )
    assert code != 0
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["n_kept"] == 1
    assert summary["any_nonempty_messages"] is False
    assert summary["ready"] is False
    assert "all_kept_rows_empty_messages" in summary["ready_fail_reasons"]
    assert out.read_text(encoding="utf-8").strip()


def test_zero_kept_rows_exits_nonzero(tmp_path: Path) -> None:
    mod = _load_filter()
    row = _by_id("drop_failed_verify")
    src = tmp_path / "in.jsonl"
    src.write_text(json.dumps(row) + "\n", encoding="utf-8")
    out = tmp_path / "filtered.jsonl"
    summary_path = tmp_path / "summary.json"
    code = mod.main([str(src), "--out", str(out), "--summary", str(summary_path)])
    assert code != 0
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["n_kept"] == 0
    assert summary["ready"] is False
    assert "zero_rows" in summary["ready_fail_reasons"]
    assert out.read_text(encoding="utf-8") == ""


def test_cli_on_fixture_is_ready_when_one_row_has_messages(tmp_path: Path) -> None:
    mod = _load_filter()
    out = tmp_path / "filtered.jsonl"
    summary_path = tmp_path / "summary.json"
    code = mod.main(
        [
            str(FIXTURE),
            "--out",
            str(out),
            "--summary",
            str(summary_path),
        ]
    )
    assert code == 0
    kept = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert [r["scenario_id"] for r in kept] == list(KEEP_IDS)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["ready"] is True
    assert summary["any_nonempty_messages"] is True
    assert summary["filter_revision"] == "DR-012"
    assert summary["prefer_correct_verdict"] is True
