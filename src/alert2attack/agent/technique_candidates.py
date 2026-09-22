"""Extract ATT&CK write candidates from evidence fetched in this run."""

from __future__ import annotations

import re
from collections.abc import Iterable

from alert2attack.knowledge.base import KnowledgeBase

_ATTACK_EVIDENCE_RE = re.compile(r"^attack-(T\d{4}(?:\.\d{3})?)$")


def technique_candidates_from_ledger(
    ledger_ids: Iterable[str],
    knowledge: KnowledgeBase,
) -> list[str]:
    """Return sorted known technique ids backed by explicit ATT&CK lookups."""
    candidates: set[str] = set()
    for evidence_id in ledger_ids:
        match = _ATTACK_EVIDENCE_RE.fullmatch(evidence_id)
        if match is None:
            continue
        technique_id = match.group(1)
        if knowledge.technique(technique_id) is not None:
            candidates.add(technique_id)
    return sorted(candidates)
