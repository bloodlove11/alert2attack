"""EXP-002 / DR-013: post-verify verdict floor on cited high-sev tactics."""

from __future__ import annotations

from alert2attack.agent.verdict_floor import apply_verdict_floor, cited_high_severity_tactics
from alert2attack.domain.casefile import CaseFile, Claim, Scope, TechniqueClaim, Verdict
from alert2attack.knowledge.base import KnowledgeBase


def _cf(
    *,
    verdict: Verdict = Verdict.NOT_ENOUGH_EVIDENCE,
    techniques: list[TechniqueClaim] | None = None,
    persistence: list[Claim] | None = None,
) -> CaseFile:
    return CaseFile(
        verdict=verdict,
        confidence="low",
        summary="Verdict-floor fixture case file.",
        techniques=list(techniques or []),
        scope=Scope(persistence=list(persistence or [])),
    )


def test_nee_with_persistence_technique_lifts_to_malicious() -> None:
    kb = KnowledgeBase.load_default()
    cf = _cf(
        techniques=[TechniqueClaim(technique_id="T1053.005", evidence=["attack-T1053.005"])],
    )
    out = apply_verdict_floor(cf, kb)
    assert out.verdict is Verdict.MALICIOUS
    assert cited_high_severity_tactics(cf, kb) >= {"persistence"}
    assert any("high-severity" in q.lower() or "malicious" in q.lower() for q in out.open_questions)


def test_execution_only_technique_does_not_lift() -> None:
    kb = KnowledgeBase.load_default()
    cf = _cf(
        techniques=[TechniqueClaim(technique_id="T1059.001", evidence=["attack-T1059.001"])],
    )
    out = apply_verdict_floor(cf, kb)
    assert out.verdict is Verdict.NOT_ENOUGH_EVIDENCE
    assert cited_high_severity_tactics(cf, kb) == frozenset()
    assert out.open_questions == []


def test_suspicious_defense_evasion_lifts_to_malicious() -> None:
    kb = KnowledgeBase.load_default()
    cf = _cf(
        verdict=Verdict.SUSPICIOUS,
        techniques=[TechniqueClaim(technique_id="T1218.005", evidence=["attack-T1218.005"])],
    )
    assert apply_verdict_floor(cf, kb).verdict is Verdict.MALICIOUS


def test_likely_benign_with_high_sev_lifts_to_malicious() -> None:
    kb = KnowledgeBase.load_default()
    cf = _cf(
        verdict=Verdict.LIKELY_BENIGN,
        techniques=[TechniqueClaim(technique_id="T1003.001", evidence=["attack-T1003.001"])],
    )
    assert apply_verdict_floor(cf, kb).verdict is Verdict.MALICIOUS


def test_malicious_is_never_downgraded() -> None:
    kb = KnowledgeBase.load_default()
    cf = _cf(verdict=Verdict.MALICIOUS)
    assert apply_verdict_floor(cf, kb).verdict is Verdict.MALICIOUS


def test_empty_techniques_and_persistence_unchanged() -> None:
    kb = KnowledgeBase.load_default()
    cf = _cf()
    out = apply_verdict_floor(cf, kb)
    assert out.verdict is Verdict.NOT_ENOUGH_EVIDENCE
    assert out.open_questions == []


def test_scope_persistence_claim_is_enough_to_floor() -> None:
    kb = KnowledgeBase.load_default()
    cf = _cf(persistence=[Claim(text="HKCU Run key", evidence=["ev-0007"])])
    assert apply_verdict_floor(cf, kb).verdict is Verdict.MALICIOUS
    assert "persistence" in cited_high_severity_tactics(cf, kb)


def test_unknown_technique_id_does_not_floor() -> None:
    kb = KnowledgeBase.load_default()
    cf = _cf(techniques=[TechniqueClaim(technique_id="T9999", evidence=["attack-T9999"])])
    assert apply_verdict_floor(cf, kb).verdict is Verdict.NOT_ENOUGH_EVIDENCE
    assert cited_high_severity_tactics(cf, kb) == frozenset()
