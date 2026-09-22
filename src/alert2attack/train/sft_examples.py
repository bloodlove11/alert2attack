"""Turn DR-012 filtered teacher-dev JSONL into Qwen chat threads for SFT.

CPU-only. Does not train, does not read the test split, does not loosen DR-012.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SMOKE_SFT_N_THRESHOLD = 8
FULL_LORA_N_THRESHOLD = 12


@dataclass(frozen=True)
class SftExample:
    scenario_id: str
    split: str
    messages: list[dict[str, Any]]


@dataclass(frozen=True)
class SftDataset:
    train: list[SftExample]
    eval: list[SftExample]
    n_cases: int
    n_train_cases: int
    holdout_ids: list[str]
    smoke: bool
    n_train_threads: int = 0
    n_eval_threads: int = 0
    dropped_empty_target: int = 0
    dropped_not_dev: int = 0
    extra: dict[str, Any] = field(default_factory=dict)


def _assistant_target(message: object) -> bool:
    if not isinstance(message, dict) or message.get("role") != "assistant":
        return False
    if message.get("tool_calls"):
        return True
    content = message.get("content")
    return isinstance(content, str) and bool(content.strip())


def _keep_thread(thread: object) -> bool:
    if not isinstance(thread, list) or len(thread) < 2:
        return False
    return _assistant_target(thread[-1])


def iter_case_threads(row: dict[str, Any]) -> list[list[dict[str, Any]]]:
    split = row.get("split")
    if split is not None and split != "dev":
        return []
    raw = row.get("messages") or []
    if not isinstance(raw, list):
        return []
    kept: list[list[dict[str, Any]]] = []
    for thread in raw:
        if _keep_thread(thread):
            kept.append([dict(m) for m in thread if isinstance(m, dict)])
    return kept


def build_sft_dataset(
    rows: list[dict[str, Any]],
    *,
    holdout_cases: int = 2,
    allow_smoke: bool = False,
    enforce_n: bool = True,
) -> SftDataset:
    by_id: dict[str, list[SftExample]] = {}
    dropped_empty_target = 0
    dropped_not_dev = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        split = row.get("split")
        if split is not None and split != "dev":
            dropped_not_dev += 1
            continue
        sid = str(row.get("scenario_id") or "")
        if not sid:
            continue
        threads = iter_case_threads(row)
        raw_threads = row.get("messages") or []
        if isinstance(raw_threads, list):
            dropped_empty_target += sum(1 for t in raw_threads if isinstance(t, list) and not _keep_thread(t))
        if not threads:
            continue
        examples = [SftExample(scenario_id=sid, split="dev", messages=th) for th in threads]
        by_id.setdefault(sid, []).extend(examples)

    case_ids = sorted(by_id)
    n_cases = len(case_ids)
    smoke = n_cases < FULL_LORA_N_THRESHOLD
    if enforce_n:
        if n_cases < SMOKE_SFT_N_THRESHOLD:
            raise ValueError(
                f"filtered N={n_cases} is below smoke SFT discuss threshold "
                f"{SMOKE_SFT_N_THRESHOLD}; do not train"
            )
        if smoke and not allow_smoke:
            raise ValueError(
                f"filtered N={n_cases} is below full LoRA threshold "
                f"{FULL_LORA_N_THRESHOLD}; pass allow_smoke=True for smoke SFT only"
            )

    n_hold = min(max(holdout_cases, 0), n_cases)
    holdout_ids = case_ids[-n_hold:] if n_hold else []
    holdout = set(holdout_ids)
    train = [ex for sid in case_ids if sid not in holdout for ex in by_id[sid]]
    eval_ex = [ex for sid in holdout_ids for ex in by_id[sid]]
    n_train_cases = n_cases - len(holdout_ids)
    return SftDataset(
        train=train,
        eval=eval_ex,
        n_cases=n_cases,
        n_train_cases=n_train_cases,
        holdout_ids=list(holdout_ids),
        smoke=smoke,
        n_train_threads=len(train),
        n_eval_threads=len(eval_ex),
        dropped_empty_target=dropped_empty_target,
        dropped_not_dev=dropped_not_dev,
    )


def dataset_to_records(ds: SftDataset) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for subset, examples in (("train", ds.train), ("eval", ds.eval)):
        for ex in examples:
            out.append(
                {
                    "scenario_id": ex.scenario_id,
                    "split": ex.split,
                    "subset": subset,
                    "messages": ex.messages,
                }
            )
    return out


def summary_dict(ds: SftDataset) -> dict[str, Any]:
    return {
        "n_cases": ds.n_cases,
        "n_train_cases": ds.n_train_cases,
        "holdout_ids": ds.holdout_ids,
        "smoke": ds.smoke,
        "n_train_threads": ds.n_train_threads,
        "n_eval_threads": ds.n_eval_threads,
        "dropped_empty_target": ds.dropped_empty_target,
        "dropped_not_dev": ds.dropped_not_dev,
        "full_lora_n_ok": ds.n_cases >= FULL_LORA_N_THRESHOLD,
        "smoke_sft_discuss_clears": ds.n_cases >= SMOKE_SFT_N_THRESHOLD,
    }
