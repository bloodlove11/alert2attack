"""Deterministic CaseFile verifier (design §5.6)."""

from __future__ import annotations

from collections.abc import Iterable

from alert2attack.domain.casefile import MAX_SUMMARY_SENTENCES, CaseFile, Claim, summary_sentence_count
from alert2attack.domain.events import EventKind
from alert2attack.domain.evidence import is_evidence_id
from alert2attack.knowledge.base import KnowledgeBase
from alert2attack.store.case_store import CaseStore
from alert2attack.tools.context import EvidenceLedger
from alert2attack.verify.models import VerificationError, VerificationReport


def _iter_claims(case_file: CaseFile) -> Iterable[tuple[str, Claim]]:
    if case_file.scope.root_process is not None:
        yield "scope.root_process", case_file.scope.root_process
    for i, claim in enumerate(case_file.scope.persistence):
        yield f"scope.persistence[{i}]", claim
    for i, entry in enumerate(case_file.timeline):
        yield f"timeline[{i}]", Claim(text=entry.text, evidence=entry.evidence)
    for i, tech in enumerate(case_file.techniques):
        yield f"techniques[{i}]", Claim(text=tech.technique_id, evidence=tech.evidence)
    for i, action in enumerate(case_file.next_actions):
        yield f"next_actions[{i}].rationale", action.rationale


def _check_evidence(
    path: str,
    evidence: list[str],
    ledger: EvidenceLedger,
    errors: list[VerificationError],
) -> None:
    if not evidence:
        errors.append(
            VerificationError(path=path, code="EMPTY_EVIDENCE", message="claim has empty evidence list")
        )
        return
    for j, eid in enumerate(evidence):
        ep = f"{path}.evidence[{j}]"
        if not is_evidence_id(eid):
            errors.append(
                VerificationError(path=ep, code="UNKNOWN_EVIDENCE", message=f"id {eid!r} fails evidence grammar")
            )
            continue
        if not ledger.has(eid):
            errors.append(
                VerificationError(
                    path=ep,
                    code="EVIDENCE_NOT_IN_LEDGER",
                    message=f"id {eid!r} was not returned by any tool in this run",
                )
            )


def verify(
    case_file: CaseFile,
    ledger: EvidenceLedger,
    store: CaseStore,
    case_id: str,
    knowledge: KnowledgeBase,
) -> VerificationReport:
    """Pure checks over the written CaseFile. Does not mutate inputs."""
    errors: list[VerificationError] = []

    for path, claim in _iter_claims(case_file):
        _check_evidence(path, list(claim.evidence), ledger, errors)

    # Techniques must exist in KB
    for i, tech in enumerate(case_file.techniques):
        if knowledge.technique(tech.technique_id) is None:
            errors.append(
                VerificationError(
                    path=f"techniques[{i}].technique_id",
                    code="UNKNOWN_TECHNIQUE",
                    message=f"technique {tech.technique_id!r} not in knowledge base",
                )
            )

    # involved_pids: each needs a cited process_create in the ledger
    cited_ids = {eid for _, claim in _iter_claims(case_file) for eid in claim.evidence}
    for pid in case_file.scope.involved_pids:
        proc_events = store.query_events(case_id, kinds=[EventKind.PROCESS_CREATE], pid=pid)
        ledger_proc = [e for e in proc_events if ledger.has(e.event_id)]
        if not ledger_proc:
            errors.append(
                VerificationError(
                    path="scope.involved_pids",
                    code="PID_UNSUPPORTED",
                    message=f"pid {pid} has no process_create in the evidence ledger",
                )
            )
            continue
        if not any(e.event_id in cited_ids for e in ledger_proc):
            errors.append(
                VerificationError(
                    path="scope.involved_pids",
                    code="PID_UNSUPPORTED",
                    message=f"pid {pid} process_create was seen but not cited in the case file",
                )
            )

    # Timeline chronological order (string ISO compare is OK for our Z timestamps)
    timestamps = [entry.ts for entry in case_file.timeline]
    if timestamps != sorted(timestamps):
        errors.append(
            VerificationError(
                path="timeline",
                code="TIMELINE_UNSORTED",
                message="timeline entries are not sorted by ts ascending",
            )
        )

    summary = case_file.summary.strip()
    if summary_sentence_count(summary) > MAX_SUMMARY_SENTENCES:
        errors.append(
            VerificationError(
                path="summary",
                code="SUMMARY_TOO_LONG",
                message="summary must be at most 3 sentences",
            )
        )

    return VerificationReport(passed=not errors, status="passed" if not errors else "degraded", errors=errors)
