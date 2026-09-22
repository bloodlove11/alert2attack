#!/usr/bin/env python3
"""Offline smoke for the eval harness (plumbing check — not headline numbers).

Generates per-scenario ScriptedChat responses that cite the alert trigger evidence,
runs ``agent-scripted`` on a small slice, and writes ``reports/``.

Live arms (optional, requires Ollama / OPENAI_API_KEY)::

    uv run python scripts/smoke_eval.py --live local --split test --limit 3
    uv run python scripts/smoke_eval.py --live teacher --split dev --limit 3
    uv run python scripts/smoke_eval.py --live b0 --split test --limit 3

Then merge JSON reports into a README-ready table::

    uv run python scripts/render_eval_table.py reports
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from alert2attack.agent.llm import ChatResponse, ScriptedChat
from alert2attack.domain.scenario import SCENARIOS_ROOT, Scenario
from alert2attack.eval.runner import ArmName, run_eval


def _scripted_casefile(scenario: Scenario) -> str:
    """Minimal valid case file citing the alert trigger (plumbing only)."""
    eid = scenario.alert.trigger_event_id
    # Prefer gold verdict when present so smoke is not a sea of mismatches;
    # this is still NOT a headline measurement — responses are oracle-ish.
    verdict = scenario.gold.verdict if scenario.gold is not None else "not_enough_evidence"
    return json.dumps(
        {
            "verdict": verdict,
            "confidence": "medium",
            "summary": f"Smoke case for {scenario.scenario_id}.",
            "timeline": [
                {
                    "ts": scenario.alert.fired_at.isoformat().replace("+00:00", "Z"),
                    "text": "alert trigger",
                    "evidence": [eid],
                }
            ],
            "techniques": [],
            "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
            "next_actions": [
                {
                    "action": "escalate",
                    "rationale": {"text": "smoke", "evidence": [eid]},
                }
            ],
            "open_questions": [],
        }
    )


def _scripted_factory(scenario: Scenario) -> ScriptedChat:
    payload = _scripted_casefile(scenario)
    return ScriptedChat(
        [
            ChatResponse(content="1. confirm alert\n2. write case"),
            ChatResponse(content="ready"),
            ChatResponse(content=payload),
            ChatResponse(content=payload),
            ChatResponse(content=payload),
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("dev", "test"), default="test")
    parser.add_argument("--limit", type=int, default=1)
    parser.add_argument("--root", type=Path, default=SCENARIOS_ROOT)
    parser.add_argument("--out", type=Path, default=Path("reports"))
    parser.add_argument(
        "--live",
        choices=("scripted", "local", "teacher", "b0"),
        default="scripted",
        help="scripted=offline smoke; local=Ollama 7B; teacher=OpenAI; b0=baseline",
    )
    args = parser.parse_args()

    arm_map: dict[str, ArmName] = {
        "scripted": "agent-scripted",
        "local": "agent-local-7b",
        "teacher": "agent-teacher",
        "b0": "b0",
    }
    arm = arm_map[args.live]
    kwargs: dict[str, object] = {
        "arm": arm,
        "split": args.split,
        "root": args.root,
        "out_dir": args.out,
        "limit": args.limit,
    }
    if args.live == "scripted":
        kwargs["scripted_factory"] = _scripted_factory
        print(
            "NOTE: scripted smoke uses oracle-ish verdicts for plumbing only — "
            "do not paste these numbers into the README headline table.",
            file=sys.stderr,
        )

    report = run_eval(**kwargs)  # type: ignore[arg-type]
    print(report.markdown_table())
    print(json.dumps({"arm": report.arm, "split": report.split, "n": report.n}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
