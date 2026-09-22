import pytest
from pydantic import ValidationError

from alert2attack.domain.casefile import (
    ActionRecommendation,
    CaseFile,
    Claim,
    NextAction,
    Scope,
    TechniqueClaim,
    TimelineEntry,
    Verdict,
    clip_summary_sentences,
    summary_sentence_count,
)

# Unbounded teacher-dev write that CaseFile rejected on raw period count (4)
# despite being two sentences (mshta.exe + T1218.005).
TEACHER_MSHTA_RETRY_SUMMARY = (
    "mshta.exe executed inline JavaScript that retrieved and invoked a remote "
    "scriptlet, matching T1218.005 proxy execution. The activity occurred on "
    "WORKSTATION5 under WORKSTATION5\\wardog and used the referenced Atomic "
    "Red Team payload."
)


def test_casefile_roundtrip() -> None:
    cf = CaseFile(
        verdict=Verdict.MALICIOUS,
        confidence="high",
        summary="Encoded PowerShell downloaded a payload. Host should be isolated.",
        timeline=[TimelineEntry(ts="2024-01-01T00:00:00Z", text="alert fired", evidence=["ev-0001"])],
        techniques=[TechniqueClaim(technique_id="T1059.001", evidence=["attack-T1059.001"])],
        scope=Scope(
            root_process=Claim(text="cmd.exe", evidence=["ev-0001"]),
            involved_pids=[10, 20],
        ),
        next_actions=[
            ActionRecommendation(
                action=NextAction.ISOLATE_HOST,
                rationale=Claim(text="active C2", evidence=["ev-0002"]),
            )
        ],
        open_questions=[],
    )
    assert CaseFile.model_validate(cf.model_dump()).verdict is Verdict.MALICIOUS


def test_claim_requires_evidence() -> None:
    with pytest.raises(ValidationError):
        Claim(text="x", evidence=[])


def test_teacher_mshta_retry_is_two_sentences_not_four_periods() -> None:
    assert TEACHER_MSHTA_RETRY_SUMMARY.count(".") == 4
    assert summary_sentence_count(TEACHER_MSHTA_RETRY_SUMMARY) == 2
    cf = CaseFile(verdict=Verdict.MALICIOUS, confidence="high", summary=TEACHER_MSHTA_RETRY_SUMMARY)
    assert cf.summary == TEACHER_MSHTA_RETRY_SUMMARY


def test_summary_with_hostname_is_two_sentences() -> None:
    text = (
        "mshta.exe retrieved a scriptlet from raw.githubusercontent.com, matching "
        "the T1218.005 proxy-execution technique. The activity is an Atomic Red Team payload."
    )
    assert text.count(".") > 3
    assert summary_sentence_count(text) == 2
    CaseFile(verdict=Verdict.MALICIOUS, confidence="high", summary=text)


def test_four_real_sentences_still_rejected() -> None:
    text = "One claim. Two claim. Three claim. Four claim."
    assert summary_sentence_count(text) == 4
    with pytest.raises(ValidationError, match="at most 3 sentences"):
        CaseFile(verdict=Verdict.SUSPICIOUS, confidence="low", summary=text)


def test_clip_keeps_first_three_real_sentences() -> None:
    text = "One claim. Two claim. Three claim. Four claim."
    assert clip_summary_sentences(text) == "One claim. Two claim. Three claim."
    # False periods must not become clip points.
    assert clip_summary_sentences(TEACHER_MSHTA_RETRY_SUMMARY) == TEACHER_MSHTA_RETRY_SUMMARY
