import json

import pytest
from pydantic import ValidationError

from alert2attack.agent.jsonutil import normalize_casefile_dict, parse_case_file
from alert2attack.domain.casefile import CaseFile, Verdict

_MINIMAL_CASEFILE = {
    "verdict": "suspicious",
    "confidence": "medium",
    "summary": "Host ran encoded PowerShell.",
    "timeline": [],
    "techniques": [],
    "scope": {},
    "next_actions": [],
    "open_questions": [],
}


def test_normalize_strips_case_id_and_name_and_defaults_confidence() -> None:
    payload = {
        "case_id": "case-001",
        "case_name": "Potential PowerShell",
        "verdict": "not_enough_evidence",
        "summary": "Ambiguous window.",
        "timeline": [],
        "techniques": [],
        "scope": {},
        "next_actions": [],
        "open_questions": [],
    }
    normalized = normalize_casefile_dict(payload)
    assert "case_id" not in normalized
    assert "case_name" not in normalized
    assert normalized["confidence"] == "low"
    cf = CaseFile.model_validate(normalized)
    assert cf.verdict.value == "not_enough_evidence"
    assert cf.techniques == []


def test_normalize_does_not_invent_verdict_or_techniques() -> None:
    payload = {"summary": "no verdict yet", "case_id": "x"}
    normalized = normalize_casefile_dict(payload)
    assert "verdict" not in normalized
    assert "techniques" not in normalized or normalized.get("techniques") in (None, [])


def test_normalize_description_alias_to_summary() -> None:
    payload = {
        "verdict": "suspicious",
        "confidence": "medium",
        "description": "Host ran encoded PowerShell.",
        "timeline": [],
        "techniques": [],
        "scope": {},
        "next_actions": [],
        "open_questions": [],
    }
    normalized = normalize_casefile_dict(payload)
    assert normalized["summary"] == "Host ran encoded PowerShell."
    assert "description" not in normalized


def test_parse_case_file_accepts_fenced_json_and_strips_extras() -> None:
    raw = "```json\n" + json.dumps({**_MINIMAL_CASEFILE, "case_id": "drop-me"}) + "\n```"
    cf = parse_case_file(raw)
    assert cf.verdict is Verdict.SUSPICIOUS
    assert cf.summary == "Host ran encoded PowerShell."
    assert cf.confidence == "medium"


def test_parse_case_file_raises_on_empty_or_invalid() -> None:
    with pytest.raises(ValueError, match="no JSON object"):
        parse_case_file("")
    with pytest.raises(ValueError, match="no JSON object"):
        parse_case_file("not json at all")


def test_parse_case_file_raises_on_schema_invalid() -> None:
    with pytest.raises(ValidationError):
        parse_case_file("{}")


def test_parse_case_file_accepts_teacher_mshta_retry_summary() -> None:
    summary = (
        "mshta.exe executed inline JavaScript that retrieved and invoked a remote "
        "scriptlet, matching T1218.005 proxy execution. The activity occurred on "
        "WORKSTATION5 under WORKSTATION5\\wardog and used the referenced Atomic "
        "Red Team payload."
    )
    payload = {
        **_MINIMAL_CASEFILE,
        "verdict": "malicious",
        "confidence": "high",
        "summary": summary,
        "techniques": [
            {"technique_id": "T1218.005", "evidence": ["attack-T1218.005"], "note": "mshta"}
        ],
    }
    cf = parse_case_file(json.dumps(payload))
    assert cf.verdict is Verdict.MALICIOUS
    assert cf.summary == summary
    assert cf.techniques[0].technique_id == "T1218.005"


def test_normalize_clips_four_real_sentences_without_inventing_claims() -> None:
    payload = {
        **_MINIMAL_CASEFILE,
        "verdict": "malicious",
        "confidence": "high",
        "summary": "One claim. Two claim. Three claim. Four claim.",
        "techniques": [
            {"technique_id": "T1218.005", "evidence": ["attack-T1218.005"], "note": "kept"}
        ],
    }
    normalized = normalize_casefile_dict(payload)
    assert normalized["summary"] == "One claim. Two claim. Three claim."
    assert normalized["verdict"] == "malicious"
    assert normalized["techniques"] == payload["techniques"]
    cf = parse_case_file(json.dumps(payload))
    assert cf.summary == "One claim. Two claim. Three claim."
    assert cf.verdict is Verdict.MALICIOUS
    assert cf.techniques[0].technique_id == "T1218.005"
