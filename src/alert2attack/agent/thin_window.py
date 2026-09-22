"""Thin boxed-window abstain ceiling (EXP-002 lever 5).

NEE twins are catalog-truncated to trigger ± parent process_create. A writer
that calls those windows malicious is labeling a truncated box, not a full
attack chain. Cap to not_enough_evidence. Never reads gold.
"""

from __future__ import annotations

from collections.abc import Sequence

from alert2attack.domain.casefile import CaseFile, Verdict
from alert2attack.domain.events import Event, EventKind

THIN_MAX_PROCESS_CREATES = 2

CEILING_NOTE = (
    "Boxed window contains only the alert trigger (and parent) process_create; "
    "follow-on telemetry is absent, so verdict is not_enough_evidence."
)


def is_thin_trigger_window(events: Sequence[Event]) -> bool:
    if not events:
        return False
    n_pc = 0
    for event in events:
        if event.kind is not EventKind.PROCESS_CREATE:
            return False
        n_pc += 1
    return 1 <= n_pc <= THIN_MAX_PROCESS_CREATES


def apply_thin_window_ceiling(case_file: CaseFile, events: Sequence[Event]) -> CaseFile:
    if not is_thin_trigger_window(events):
        return case_file
    if case_file.verdict is Verdict.NOT_ENOUGH_EVIDENCE:
        return case_file
    questions = list(case_file.open_questions)
    if CEILING_NOTE not in questions:
        questions.append(CEILING_NOTE)
    return case_file.model_copy(
        update={"verdict": Verdict.NOT_ENOUGH_EVIDENCE, "open_questions": questions}
    )
