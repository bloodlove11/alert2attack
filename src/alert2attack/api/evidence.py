"""Resolve a citation back to the thing the agent actually fetched.

Every claim in a case file cites evidence ids (``ev-0042``, ``rule-<slug>``,
``attack-T1003``). The verifier guarantees those ids were in the run's ledger;
this module turns one back into the underlying event, Sigma rule or ATT&CK
technique so a human can check the agent's work rather than trust it.

Ledger membership is re-derived from the run's own trace, not from a live
ledger object: the answer must be "what did this run actually see", and the
trace is the persisted record of exactly that.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from alert2attack.api.scenarios import case_store_for
from alert2attack.domain.events import Event
from alert2attack.domain.evidence import is_evidence_id
from alert2attack.knowledge.base import AttackTechnique, KnowledgeBase, SigmaRule

EvidenceKind = Literal["event", "sigma_rule", "attack_technique"]


class EvidenceResolution(BaseModel):
    """One resolved citation. Exactly one of the payload fields is populated."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    kind: EvidenceKind
    first_seen_tool_seq: int | None = None
    event: Event | None = None
    rule: SigmaRule | None = None
    technique: AttackTechnique | None = None


class EvidenceNotInLedger(KeyError):
    """Cited, but this run never fetched it. The verifier should have caught it."""


class EvidenceUnresolvable(KeyError):
    """In the ledger, but the underlying record is gone. Always a bug."""


@lru_cache(maxsize=1)
def knowledge() -> KnowledgeBase:
    return KnowledgeBase.load_default()


def evidence_kind(evidence_id: str) -> EvidenceKind:
    if evidence_id.startswith("ev-"):
        return "event"
    if evidence_id.startswith("rule-"):
        return "sigma_rule"
    return "attack_technique"


def ledger_from_trace(trace: dict[str, Any]) -> dict[str, int]:
    """Map evidence id -> the tool-call seq that first returned it."""
    first_seen: dict[str, int] = {}
    for call in trace.get("tool_calls", []):
        if not call.get("ok", False):
            continue
        for eid in call.get("evidence_ids", []):
            first_seen.setdefault(eid, call["seq"])
    return first_seen


def resolve(
    *,
    evidence_id: str,
    scenario_id: str,
    trace: dict[str, Any],
) -> EvidenceResolution:
    if not is_evidence_id(evidence_id):
        raise ValueError(f"not an evidence id: {evidence_id!r}")

    ledger = ledger_from_trace(trace)
    if evidence_id not in ledger:
        raise EvidenceNotInLedger(evidence_id)
    seq = ledger[evidence_id]
    kind = evidence_kind(evidence_id)

    if kind == "event":
        store = case_store_for(scenario_id)
        try:
            event = store.get_event(scenario_id, evidence_id)
        finally:
            store.close()
        if event is None:
            raise EvidenceUnresolvable(evidence_id)
        return EvidenceResolution(
            evidence_id=evidence_id, kind=kind, first_seen_tool_seq=seq, event=event
        )

    if kind == "sigma_rule":
        rule = knowledge().rule(evidence_id.removeprefix("rule-"))
        if rule is None:
            raise EvidenceUnresolvable(evidence_id)
        return EvidenceResolution(
            evidence_id=evidence_id, kind=kind, first_seen_tool_seq=seq, rule=rule
        )

    technique = knowledge().technique(evidence_id.removeprefix("attack-"))
    if technique is None:
        raise EvidenceUnresolvable(evidence_id)
    return EvidenceResolution(
        evidence_id=evidence_id, kind=kind, first_seen_tool_seq=seq, technique=technique
    )
