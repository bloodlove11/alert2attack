"""Evaluation harness (Phase 5)."""

from alert2attack.eval.metrics import AggregateReport, CaseScore, aggregate, score_case
from alert2attack.eval.runner import run_eval

__all__ = [
    "AggregateReport",
    "CaseScore",
    "aggregate",
    "run_eval",
    "score_case",
]
