"""Deterministic post-verify verdict floor (EXP-002 / DR-013).

Lifts a conservative write to malicious when the case file already cites
high-severity ATT&CK tactics (or surviving scope.persistence). Never invents
techniques, never reads gold, never downgrades malicious.
"""

from __future__ import annotations

from alert2attack.domain.casefile import CaseFile, Verdict
from alert2attack.knowledge.base import KnowledgeBase

HIGH_SEV_TACTICS = frozenset(
    {
        "persistence",
        "privilege-escalation",
        "credential-access",
        "defense-evasion",
        "command-and-control",
        "lateral-movement",
    }
)

FLOOR_NOTE = (
    "Cited high-severity ATT&CK tactics (persistence / privilege-escalation / "
    "credential-access / defense-evasion / command-and-control / lateral-movement) "
    "require verdict malicious."
)


def _norm_tactic(tactic: str) -> str:
    return tactic.strip().lower().replace("_", "-")


def cited_high_severity_tactics(case_file: CaseFile, knowledge: KnowledgeBase) -> frozenset[str]:
    found: set[str] = set()
    if case_file.scope.persistence:
        found.add("persistence")
    for tech in case_file.techniques:
        rec = knowledge.technique(tech.technique_id)
        if rec is None:
            continue
        for tactic in rec.tactics:
            norm = _norm_tactic(tactic)
            if norm in HIGH_SEV_TACTICS:
                found.add(norm)
    return frozenset(found)


def apply_verdict_floor(case_file: CaseFile, knowledge: KnowledgeBase) -> CaseFile:
    if case_file.verdict is Verdict.MALICIOUS:
        return case_file
    if not cited_high_severity_tactics(case_file, knowledge):
        return case_file
    questions = list(case_file.open_questions)
    if FLOOR_NOTE not in questions:
        questions.append(FLOOR_NOTE)
    return case_file.model_copy(update={"verdict": Verdict.MALICIOUS, "open_questions": questions})
