#!/usr/bin/env python3
"""Merge eval report JSON files into one README-ready markdown table.

Picks the newest report per (arm, split). Usage::

    uv run python scripts/render_eval_table.py reports
    uv run python scripts/render_eval_table.py reports --out reports/SUMMARY.md
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _load_reports(root: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in sorted(root.glob("*-*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        # runner writes {"report": AggregateReport.to_dict(), ...}
        payload = data.get("report") if isinstance(data.get("report"), dict) else data
        if not isinstance(payload, dict) or "arm" not in payload:
            continue
        row = dict(payload)
        row["_path"] = str(path)
        row["_mtime"] = path.stat().st_mtime
        rows.append(row)
    return rows


def _newest_per_arm_split(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    best: dict[tuple[str, str], dict[str, object]] = {}
    for row in rows:
        key = (str(row["arm"]), str(row["split"]))
        prev = best.get(key)
        # Prefer higher mtime; on ties keep the later path (rows are sorted by name).
        if prev is None or float(row["_mtime"]) >= float(prev["_mtime"]):
            best[key] = row
    return [best[k] for k in sorted(best)]


def render(rows: list[dict[str, object]]) -> str:
    header = (
        "| Arm | Split | N | Verdict acc | Mean cost | Citation post | Key-pid recall | Action safety |\n"
        "|---|---|---:|---:|---:|---:|---:|---:|"
    )
    if not rows:
        body = "| _(no reports yet)_ | — | — | — | — | — | — | — |"
        return header + "\n" + body

    lines: list[str] = []
    for r in rows:
        lines.append(
            f"| `{r['arm']}` | {r['split']} | {r['n']} | "
            f"{float(r['verdict_accuracy']):.2f} | {float(r['mean_verdict_cost']):.2f} | "
            f"{float(r['mean_citation_validity_post']):.2f} | "
            f"{float(r['mean_key_pid_recall']):.2f} | {float(r['action_safety_rate']):.2f} |"
        )
    return header + "\n" + "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports_dir", type=Path, nargs="?", default=Path("reports"))
    parser.add_argument("--out", type=Path, default=None, help="Optional file to write")
    args = parser.parse_args()

    if not args.reports_dir.is_dir():
        text = render([])
        print(text)
        if args.out is not None:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(text + "\n", encoding="utf-8")
        return 0

    table = render(_newest_per_arm_split(_load_reports(args.reports_dir)))
    print(table)
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(table + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
