#!/usr/bin/env python3
"""Filter teacher-dev distill JSONL with locked DR-012 rules.

Draft helper only. Does not train, does not fetch, does not export test rows.

Keep (citation_post ≥ 0.9, split=dev only):

* ``verification_status in {passed, repaired}`` even if tool/budget exhausted
* ``verification_status == degraded`` only if citation ≥ 0.9 **and** verdict_match
  (``case_file.verdict`` equals ``gold_verdict``)

``--prefer-correct-verdict`` defaults **on**: drop verdict mismatches for all
statuses. Degraded mismatches are counted as ``degraded_no_verdict_match``
even when prefer-correct is off (DR-012 hard rule).

``distill_record`` (``src/alert2attack/eval/distill.py``) does **not** store
``citation_validity_post``. That score lives on eval ``CaseScore`` /
``reports/*.json``. This script uses ``row.citation_validity_post`` (or
``citation_post``) when present; otherwise it recomputes the frozen metric
``citation_validity(case_file, ledger)`` with
``ledger = trace.tool_calls[].evidence_ids`` (same as ``eval.runner``).

Smoke SFT discuss: filtered N ≥ 8. Full LoRA still needs filtered N ≥ 12
via a later named re-export (higher repair/tool budget). N=9 is **not**
training-ready for full LoRA. Neither threshold is a launch approval.

Usage::

    uv run python scripts/filter_teacher_dev_distill.py \\
        reports/distill/teacher-dev.jsonl \\
        --out reports/distill/teacher-dev.filtered.jsonl

Exits non-zero if the output has zero rows or every kept row has empty
``messages`` (SFT-ready=false). Kill flags in the summary JSON do not
change the exit code.

See ``docs/experiments/DATA_CARD-teacher-dev-v0.md``. Status: DRAFT / NOT READY
until a filtered artifact is produced under DR-012. Not a launch approval.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

CITATION_THRESHOLD = 0.9
SMOKE_SFT_N_THRESHOLD = 8
FULL_LORA_N_THRESHOLD = 12
FILTER_REVISION = "DR-012"
OK_VERIFICATION = frozenset({"passed", "repaired"})
DEGRADED_STATUS = "degraded"
DROP_REASONS = (
    "invalid_row",
    "not_dev_split",
    "bad_verification",
    "citation_unavailable",
    "citation_below_threshold",
    "verdict_mismatch",
    "degraded_no_verdict_match",
)
CITATION_FIELD_PATH = (
    "row.citation_validity_post or row.citation_post if present; "
    "else recomputed as metrics.citation_validity(case_file, ledger) "
    "with ledger = trace.tool_calls[].evidence_ids "
    "(distill_record does not store citation_post)"
)
DRAFT_STATUS = (
    "DRAFT / NOT READY — DR-012 locked. A local filtered artifact is not a "
    "launch approval. Full LoRA still needs filtered N ≥ 12."
)


def _as_float(value: object) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _ledger_ids(row: dict[str, Any]) -> set[str]:
    trace = row.get("trace")
    if not isinstance(trace, dict):
        return set()
    ids: set[str] = set()
    for call in trace.get("tool_calls") or []:
        if isinstance(call, dict):
            ids.update(str(eid) for eid in (call.get("evidence_ids") or []))
    return ids


def _evidence_slots(case_file: dict[str, Any]) -> list[str]:
    slots: list[str] = []
    scope = case_file.get("scope") if isinstance(case_file.get("scope"), dict) else {}
    root = scope.get("root_process") if isinstance(scope, dict) else None
    if isinstance(root, dict):
        slots.extend(str(eid) for eid in (root.get("evidence") or []))
    if isinstance(scope, dict):
        for claim in scope.get("persistence") or []:
            if isinstance(claim, dict):
                slots.extend(str(eid) for eid in (claim.get("evidence") or []))
    for entry in case_file.get("timeline") or []:
        if isinstance(entry, dict):
            slots.extend(str(eid) for eid in (entry.get("evidence") or []))
    for tech in case_file.get("techniques") or []:
        if isinstance(tech, dict):
            slots.extend(str(eid) for eid in (tech.get("evidence") or []))
    for action in case_file.get("next_actions") or []:
        if not isinstance(action, dict):
            continue
        rationale = action.get("rationale")
        if isinstance(rationale, dict):
            slots.extend(str(eid) for eid in (rationale.get("evidence") or []))
    return slots


def _recompute_citation(case_file: dict[str, Any], ledger: set[str]) -> float:
    try:
        from alert2attack.domain.casefile import CaseFile
        from alert2attack.eval.metrics import citation_validity

        return citation_validity(CaseFile.model_validate(case_file), ledger)
    except (TypeError, ValueError, KeyError):
        slots = _evidence_slots(case_file)
        if not slots:
            return 1.0
        return sum(1 for eid in slots if eid in ledger) / len(slots)


def citation_post(row: dict[str, Any]) -> float | None:
    """Resolve citation_post from an explicit score or recompute it."""
    for key in ("citation_validity_post", "citation_post"):
        if key in row and row[key] is not None:
            return _as_float(row[key])
    scores = row.get("scores")
    if isinstance(scores, dict):
        for key in ("citation_validity_post", "citation_post"):
            if key in scores and scores[key] is not None:
                return _as_float(scores[key])
    case_file = row.get("case_file")
    if not isinstance(case_file, dict):
        return None
    return _recompute_citation(case_file, _ledger_ids(row))


def _message_nonempty(msg: dict[str, Any]) -> bool:
    content = msg.get("content")
    if isinstance(content, str) and content.strip():
        return True
    return bool(msg.get("tool_calls"))


def _messages_nonempty(messages: object) -> bool:
    if not messages:
        return False
    if isinstance(messages, dict):
        return _message_nonempty(messages)
    if isinstance(messages, list):
        return any(_messages_nonempty(item) for item in messages)
    return False


def has_nonempty_messages(row: dict[str, Any]) -> bool:
    return _messages_nonempty(row.get("messages"))


def _verification_status(row: dict[str, Any]) -> str | None:
    if row.get("verification_status") is not None:
        return str(row["verification_status"])
    nested = row.get("verification")
    if isinstance(nested, dict) and nested.get("status") is not None:
        return str(nested["status"])
    return None


def _predicted_verdict(row: dict[str, Any]) -> str | None:
    case_file = row.get("case_file")
    pred = case_file.get("verdict") if isinstance(case_file, dict) else None
    if pred is None:
        return None
    return str(pred)


def _verdict_match(row: dict[str, Any]) -> bool:
    gold = row.get("gold_verdict")
    pred = _predicted_verdict(row)
    if gold is None or pred is None:
        return False
    return str(pred) == str(gold)


def _verdict_mismatch(row: dict[str, Any]) -> bool:
    gold = row.get("gold_verdict")
    pred = _predicted_verdict(row)
    if gold is None or pred is None:
        return False
    return str(pred) != str(gold)


def drop_reason(row: object, *, prefer_correct_verdict: bool) -> str | None:
    """First matching DR-012 drop reason, or None to keep.

    Tool/budget exhaustion is **not** a drop for passed/repaired (or for
    degraded that otherwise qualify).
    """
    if not isinstance(row, dict):
        return "invalid_row"
    split = row.get("split")
    if split is not None and str(split) != "dev":
        return "not_dev_split"
    status = _verification_status(row)
    if status not in OK_VERIFICATION and status != DEGRADED_STATUS:
        return "bad_verification"
    cite = citation_post(row)
    if cite is None:
        return "citation_unavailable"
    if cite < CITATION_THRESHOLD:
        return "citation_below_threshold"
    if status == DEGRADED_STATUS and not _verdict_match(row):
        return "degraded_no_verdict_match"
    if prefer_correct_verdict and _verdict_mismatch(row):
        return "verdict_mismatch"
    return None


def filter_records(
    rows: Iterable[object],
    *,
    prefer_correct_verdict: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    kept: list[dict[str, Any]] = []
    dropped_by_reason = {reason: 0 for reason in DROP_REASONS}
    n_in = 0
    for row in rows:
        n_in += 1
        reason = drop_reason(row, prefer_correct_verdict=prefer_correct_verdict)
        if reason is None:
            assert isinstance(row, dict)
            kept.append(row)
        else:
            dropped_by_reason[reason] = dropped_by_reason.get(reason, 0) + 1
    n_kept = len(kept)
    n_with_msg = sum(1 for row in kept if has_nonempty_messages(row))
    degraded_kept = sum(1 for row in kept if _verification_status(row) == DEGRADED_STATUS)
    ready_fail: list[str] = []
    if n_kept == 0:
        ready_fail.append("zero_rows")
    elif n_with_msg == 0:
        ready_fail.append("all_kept_rows_empty_messages")
    summary: dict[str, Any] = {
        "n_in": n_in,
        "n_kept": n_kept,
        "n_dropped": n_in - n_kept,
        "dropped_by_reason": dropped_by_reason,
        "degraded_kept": degraded_kept,
        "any_nonempty_messages": n_with_msg > 0,
        "n_kept_with_nonempty_messages": n_with_msg,
        "ready": not ready_fail,
        "ready_fail_reasons": ready_fail,
        "filter_revision": FILTER_REVISION,
        "smoke_sft_n_threshold": SMOKE_SFT_N_THRESHOLD,
        "full_lora_n_threshold": FULL_LORA_N_THRESHOLD,
        "kill_filtered_n_lt_8": n_kept < SMOKE_SFT_N_THRESHOLD,
        "kill_filtered_n_lt_12": n_kept < FULL_LORA_N_THRESHOLD,
        "smoke_sft_discuss_clears": n_kept >= SMOKE_SFT_N_THRESHOLD,
        "full_lora_n_ok": n_kept >= FULL_LORA_N_THRESHOLD,
        "prefer_correct_verdict": prefer_correct_verdict,
        "citation_field_path": CITATION_FIELD_PATH,
        "status": DRAFT_STATUS,
    }
    return kept, summary


def _read_jsonl(path: Path) -> list[object]:
    rows: list[object] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            rows.append(line)
    return rows


def _write_jsonl(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, default=str) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Teacher-dev JSONL path (reports/ is gitignored)")
    parser.add_argument("--out", "-o", type=Path, required=True, help="Filtered JSONL output path")
    parser.add_argument(
        "--summary",
        type=Path,
        default=None,
        help="Summary JSON path (default: <out> with .summary.json suffix)",
    )
    parser.add_argument(
        "--prefer-correct-verdict",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "DR-012 default on: drop rows whose case_file.verdict does not match "
            "gold_verdict when both are present. Degraded rows still require a "
            "verdict match even with --no-prefer-correct-verdict."
        ),
    )
    args = parser.parse_args(argv)

    if not args.input.is_file():
        print(f"input JSONL not found: {args.input}", file=sys.stderr)
        return 2

    kept, summary = filter_records(
        _read_jsonl(args.input),
        prefer_correct_verdict=bool(args.prefer_correct_verdict),
    )
    summary["input"] = str(args.input)
    summary["output"] = str(args.out)
    summary_path = args.summary if args.summary is not None else args.out.with_suffix(args.out.suffix + ".summary.json")
    summary["summary"] = str(summary_path)

    _write_jsonl(args.out, kept)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    headline = (
        "n_in",
        "n_kept",
        "ready",
        "ready_fail_reasons",
        "filter_revision",
        "kill_filtered_n_lt_8",
        "kill_filtered_n_lt_12",
        "smoke_sft_discuss_clears",
        "full_lora_n_ok",
        "status",
    )
    print(json.dumps({k: summary[k] for k in headline}))
    return 0 if summary["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
