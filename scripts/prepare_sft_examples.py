#!/usr/bin/env python3
"""Materialize SFT JSONL from a DR-012 filtered teacher-dev export.

Does not train. Never reads --split test rows. --allow-smoke is required when
filtered N is 8–11 (EXP-004 smoke). N<8 is a hard kill.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from alert2attack.train.sft_examples import build_sft_dataset, dataset_to_records, summary_dict


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="DR-012 filtered teacher-dev JSONL")
    parser.add_argument("--out", "-o", type=Path, required=True)
    parser.add_argument("--summary", type=Path, default=None)
    parser.add_argument("--holdout-cases", type=int, default=2)
    parser.add_argument(
        "--allow-smoke",
        action="store_true",
        help="Permit filtered N in [8, 12). Required for EXP-004 smoke QLoRA.",
    )
    args = parser.parse_args(argv)
    if not args.input.is_file():
        print(f"input JSONL not found: {args.input}", file=sys.stderr)
        return 2
    ds = build_sft_dataset(
        _read_jsonl(args.input),
        holdout_cases=args.holdout_cases,
        allow_smoke=bool(args.allow_smoke),
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for rec in dataset_to_records(ds):
            handle.write(json.dumps(rec) + "\n")
    summary = summary_dict(ds)
    summary["input"] = str(args.input)
    summary["output"] = str(args.out)
    summary_path = args.summary if args.summary is not None else args.out.with_suffix(args.out.suffix + ".summary.json")
    summary["summary"] = str(summary_path)
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    headline = {
        "n_cases": summary["n_cases"],
        "n_train_cases": summary["n_train_cases"],
        "n_train_threads": summary["n_train_threads"],
        "smoke": summary["smoke"],
        "full_lora_n_ok": summary["full_lora_n_ok"],
    }
    print(json.dumps(headline))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
