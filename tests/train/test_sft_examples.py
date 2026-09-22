"""Build SFT threads from a DR-012 filtered teacher-dev JSONL. No GPU."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from alert2attack.train.sft_examples import build_sft_dataset

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "train" / "sft-threads-sample.jsonl"


def _rows() -> list[dict]:
    return [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line.strip()]


def _n_dev_cases(n: int) -> list[dict]:
    template = next(r for r in _rows() if r["scenario_id"] == "case_a_write")
    out: list[dict] = []
    for i in range(n):
        row = deepcopy(template)
        row["scenario_id"] = f"case_{i:02d}"
        out.append(row)
    return out


def test_drops_test_split_and_empty_assistant_targets() -> None:
    ds = build_sft_dataset(_rows(), holdout_cases=0, allow_smoke=True, enforce_n=False)
    ids = {ex.scenario_id for ex in ds.train}
    assert "case_test_held_out" not in ids
    assert "case_c_empty_assistant" not in ids
    assert "case_a_write" in ids
    assert "case_b_tools" in ids


def test_keeps_tool_call_turns_with_empty_content() -> None:
    ds = build_sft_dataset(_rows(), holdout_cases=0, allow_smoke=True, enforce_n=False)
    b_threads = [ex.messages for ex in ds.train if ex.scenario_id == "case_b_tools"]
    assert len(b_threads) == 2
    assert b_threads[0][-1]["tool_calls"][0]["function"]["name"] == "get_process"
    assert b_threads[1][-1]["content"] == '{"verdict":"malicious"}'


def test_holdout_is_last_two_sorted_dev_ids_never_test() -> None:
    ds = build_sft_dataset(_rows(), holdout_cases=2, allow_smoke=True, enforce_n=False)
    assert ds.n_cases == 4  # a,b,d,e — c dropped (empty), test dropped
    assert ds.holdout_ids == ["case_d_write", "case_e_write"]
    train_ids = {ex.scenario_id for ex in ds.train}
    eval_ids = {ex.scenario_id for ex in ds.eval}
    assert train_ids == {"case_a_write", "case_b_tools"}
    assert eval_ids == {"case_d_write", "case_e_write"}
    assert all(ex.split == "dev" for ex in ds.train + ds.eval)


def test_refuses_n_below_smoke_threshold() -> None:
    with pytest.raises(ValueError, match="filtered N"):
        build_sft_dataset(_n_dev_cases(7), holdout_cases=0, allow_smoke=True)


def test_refuses_full_lora_when_n_lt_12() -> None:
    with pytest.raises(ValueError, match="allow_smoke"):
        build_sft_dataset(_n_dev_cases(11), holdout_cases=2, allow_smoke=False)


def test_smoke_allows_n_11() -> None:
    ds = build_sft_dataset(_n_dev_cases(11), holdout_cases=2, allow_smoke=True)
    assert ds.n_cases == 11
    assert ds.smoke is True
    assert len(ds.holdout_ids) == 2
    assert ds.n_train_cases == 9


def test_full_lora_n_14_does_not_need_allow_smoke() -> None:
    ds = build_sft_dataset(_n_dev_cases(14), holdout_cases=2, allow_smoke=False)
    assert ds.n_cases == 14
    assert ds.smoke is False
    assert ds.n_train_cases == 12
    assert len(ds.holdout_ids) == 2
