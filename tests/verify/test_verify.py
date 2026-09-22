from alert2attack.domain.casefile import CaseFile, Claim, Scope, TimelineEntry, Verdict
from alert2attack.domain.events import EventKind
from alert2attack.knowledge.base import KnowledgeBase
from alert2attack.store.case_store import CaseStore
from alert2attack.tools.context import EvidenceLedger, ToolCallRecord
from alert2attack.verify import degrade_casefile, verify


def _ledger_with(*ids: str) -> EvidenceLedger:
    ledger = EvidenceLedger()
    ledger.record(
        ToolCallRecord(
            seq=1,
            tool="get_alert",
            args={},
            ok=True,
            evidence_ids=list(ids),
            error=None,
            duration_ms=1.0,
        )
    )
    return ledger


def test_verify_passes_clean_casefile(downloader_scenario) -> None:  # type: ignore[no-untyped-def]
    store = CaseStore()
    store.load_case(downloader_scenario.public())
    # Seed ledger with real event ids from the fixture
    procs = store.query_events(downloader_scenario.scenario_id, kinds=[EventKind.PROCESS_CREATE], pid=5288)
    assert procs
    eid = procs[0].event_id
    ledger = _ledger_with(eid)
    kb = KnowledgeBase.load_default()
    cf = CaseFile(
        verdict=Verdict.MALICIOUS,
        confidence="high",
        summary="Encoded PowerShell downloaded a payload. Isolate the host.",
        timeline=[TimelineEntry(ts="2024-03-12T10:00:00Z", text="ps launch", evidence=[eid])],
        techniques=[],
        scope=Scope(
            root_process=Claim(text="powershell", evidence=[eid]),
            involved_pids=[5288],
        ),
        next_actions=[],
        open_questions=[],
    )
    report = verify(cf, ledger, store, downloader_scenario.scenario_id, kb)
    assert report.passed
    assert report.errors == []


def test_verify_flags_fabricated_evidence(downloader_scenario) -> None:  # type: ignore[no-untyped-def]
    store = CaseStore()
    store.load_case(downloader_scenario.public())
    ledger = _ledger_with("ev-0004")
    kb = KnowledgeBase.load_default()
    cf = CaseFile(
        verdict=Verdict.MALICIOUS,
        confidence="high",
        summary="Something happened.",
        timeline=[TimelineEntry(ts="2024-03-12T10:00:00Z", text="x", evidence=["ev-9999"])],
        scope=Scope(),
    )
    report = verify(cf, ledger, store, downloader_scenario.scenario_id, kb)
    assert not report.passed
    assert any(e.code == "EVIDENCE_NOT_IN_LEDGER" for e in report.errors)


def test_verify_ignores_false_periods_in_summary(downloader_scenario) -> None:  # type: ignore[no-untyped-def]
    store = CaseStore()
    store.load_case(downloader_scenario.public())
    procs = store.query_events(downloader_scenario.scenario_id, kinds=[EventKind.PROCESS_CREATE], pid=5288)
    eid = procs[0].event_id
    ledger = _ledger_with(eid)
    kb = KnowledgeBase.load_default()
    summary = (
        "mshta.exe executed inline JavaScript that retrieved and invoked a remote "
        "scriptlet, matching T1218.005 proxy execution. The activity occurred on "
        "WORKSTATION5 under WORKSTATION5\\wardog and used the referenced Atomic "
        "Red Team payload."
    )
    cf = CaseFile(
        verdict=Verdict.MALICIOUS,
        confidence="high",
        summary=summary,
        timeline=[TimelineEntry(ts="2024-03-12T10:00:00Z", text="ps launch", evidence=[eid])],
        techniques=[],
        scope=Scope(root_process=Claim(text="powershell", evidence=[eid]), involved_pids=[5288]),
        next_actions=[],
        open_questions=[],
    )
    report = verify(cf, ledger, store, downloader_scenario.scenario_id, kb)
    assert report.passed
    assert not any(e.code == "SUMMARY_TOO_LONG" for e in report.errors)


def test_verify_still_flags_four_real_sentences(downloader_scenario) -> None:  # type: ignore[no-untyped-def]
    store = CaseStore()
    store.load_case(downloader_scenario.public())
    procs = store.query_events(downloader_scenario.scenario_id, kinds=[EventKind.PROCESS_CREATE], pid=5288)
    eid = procs[0].event_id
    ledger = _ledger_with(eid)
    kb = KnowledgeBase.load_default()
    cf = CaseFile.model_construct(
        verdict=Verdict.MALICIOUS,
        confidence="high",
        summary="One claim. Two claim. Three claim. Four claim.",
        timeline=[TimelineEntry(ts="2024-03-12T10:00:00Z", text="ps launch", evidence=[eid])],
        techniques=[],
        scope=Scope(root_process=Claim(text="powershell", evidence=[eid]), involved_pids=[5288]),
        next_actions=[],
        open_questions=[],
    )
    report = verify(cf, ledger, store, downloader_scenario.scenario_id, kb)
    assert not report.passed
    assert any(e.code == "SUMMARY_TOO_LONG" for e in report.errors)


def test_degrade_strips_bad_claims(downloader_scenario) -> None:  # type: ignore[no-untyped-def]
    store = CaseStore()
    store.load_case(downloader_scenario.public())
    ledger = _ledger_with("ev-0004")
    kb = KnowledgeBase.load_default()
    cf = CaseFile(
        verdict=Verdict.MALICIOUS,
        confidence="high",
        summary="Mixed good and bad citations.",
        timeline=[
            TimelineEntry(ts="2024-03-12T10:00:00Z", text="good", evidence=["ev-0004"]),
            TimelineEntry(ts="2024-03-12T10:01:00Z", text="bad", evidence=["ev-9999"]),
        ],
        scope=Scope(),
    )
    cleaned, report = degrade_casefile(
        cf, ledger, store=store, case_id=downloader_scenario.scenario_id, knowledge=kb, prior_errors=[]
    )
    assert len(cleaned.timeline) == 1
    assert cleaned.timeline[0].evidence == ["ev-0004"]
    assert report.stripped_claims >= 1
    assert report.status == "degraded"
