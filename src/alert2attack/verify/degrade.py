"""Strip unsupported claims so a CaseFile never ships fabricated citations."""

from __future__ import annotations

from alert2attack.domain.casefile import (
    ActionRecommendation,
    CaseFile,
    Claim,
    Scope,
    TechniqueClaim,
    TimelineEntry,
    Verdict,
)
from alert2attack.domain.events import EventKind
from alert2attack.domain.evidence import is_evidence_id
from alert2attack.knowledge.base import KnowledgeBase
from alert2attack.store.case_store import CaseStore
from alert2attack.tools.context import EvidenceLedger
from alert2attack.verify.models import VerificationError, VerificationReport, VerificationStatus
from alert2attack.verify.verify import verify


def _filter_evidence(evidence: list[str], ledger: EvidenceLedger) -> list[str]:
    return [eid for eid in evidence if is_evidence_id(eid) and ledger.has(eid)]


def _keep_claim(claim: Claim, ledger: EvidenceLedger) -> Claim | None:
    kept = _filter_evidence(list(claim.evidence), ledger)
    if not kept:
        return None
    return claim.model_copy(update={"evidence": kept})


def degrade_casefile(
    case_file: CaseFile,
    ledger: EvidenceLedger,
    *,
    store: CaseStore,
    case_id: str,
    knowledge: KnowledgeBase,
    prior_errors: list[VerificationError] | None = None,
    repairs_used: int = 0,
) -> tuple[CaseFile, VerificationReport]:
    """Drop claims whose evidence is not in the ledger; force NEE if nothing solid remains."""
    stripped = 0

    root = None
    if case_file.scope.root_process is not None:
        root = _keep_claim(case_file.scope.root_process, ledger)
        if root is None:
            stripped += 1

    persistence: list[Claim] = []
    for claim in case_file.scope.persistence:
        kept = _keep_claim(claim, ledger)
        if kept is None:
            stripped += 1
        else:
            persistence.append(kept)

    timeline: list[TimelineEntry] = []
    for entry in case_file.timeline:
        kept_ids = _filter_evidence(list(entry.evidence), ledger)
        if not kept_ids:
            stripped += 1
            continue
        timeline.append(entry.model_copy(update={"evidence": kept_ids}))

    techniques: list[TechniqueClaim] = []
    for tech in case_file.techniques:
        if knowledge.technique(tech.technique_id) is None:
            stripped += 1
            continue
        kept_ids = _filter_evidence(list(tech.evidence), ledger)
        if not kept_ids:
            stripped += 1
            continue
        techniques.append(tech.model_copy(update={"evidence": kept_ids}))

    actions: list[ActionRecommendation] = []
    for action in case_file.next_actions:
        kept = _keep_claim(action.rationale, ledger)
        if kept is None:
            stripped += 1
            continue
        actions.append(action.model_copy(update={"rationale": kept}))

    cited = {eid for e in timeline for eid in e.evidence}
    if root:
        cited.update(root.evidence)
    for claim in persistence:
        cited.update(claim.evidence)
    for tech in techniques:
        cited.update(tech.evidence)
    for action in actions:
        cited.update(action.rationale.evidence)

    supported_pids: list[int] = []
    for pid in case_file.scope.involved_pids:
        procs = store.query_events(case_id, kinds=[EventKind.PROCESS_CREATE], pid=pid)
        if any(ledger.has(e.event_id) and e.event_id in cited for e in procs):
            supported_pids.append(pid)
        else:
            stripped += 1

    open_questions = list(case_file.open_questions)
    verdict = case_file.verdict
    confidence = case_file.confidence
    if stripped:
        note = f"Verifier stripped {stripped} unsupported claim(s) or pid(s)."
        if note not in open_questions:
            open_questions.append(note)
        if not timeline and root is None and not techniques:
            verdict = Verdict.NOT_ENOUGH_EVIDENCE
            confidence = "low"
            msg = "Case file degraded: insufficient cited evidence remained."
            if msg not in open_questions:
                open_questions.append(msg)

    cleaned = CaseFile(
        verdict=verdict,
        confidence=confidence,
        summary=case_file.summary,
        timeline=sorted(timeline, key=lambda e: e.ts),
        techniques=techniques,
        scope=Scope(
            root_process=root,
            involved_pids=supported_pids,
            persistence=persistence,
            beyond_process=case_file.scope.beyond_process,
        ),
        next_actions=actions,
        open_questions=open_questions,
    )
    report = verify(cleaned, ledger, store, case_id, knowledge)
    if report.passed and stripped == 0 and repairs_used == 0:
        status: VerificationStatus = "passed"
    elif report.passed and repairs_used > 0 and stripped == 0:
        status = "repaired"
    else:
        status = "degraded"
    return cleaned, VerificationReport(
        passed=report.passed,
        status=status,
        errors=report.errors,
        pre_repair_errors=list(prior_errors or []),
        repairs_used=repairs_used,
        stripped_claims=stripped,
    )
