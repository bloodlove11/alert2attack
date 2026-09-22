import pytest
from pydantic import BaseModel, ValidationError

from alert2attack.domain.evidence import (
    EvidenceId,
    is_evidence_id,
    rule_evidence_id,
    technique_evidence_id,
)


@pytest.mark.parametrize(
    "value",
    ["ev-0001", "ev-123456", "rule-win_powershell_encoded_command", "attack-T1059", "attack-T1059.001"],
)
def test_valid_ids(value: str) -> None:
    assert is_evidence_id(value)


@pytest.mark.parametrize(
    "value",
    ["ev-1", "EV-0001", "ev-0001 ", "rule-", "rule-With Space", "attack-1059", "attack-T105", "event-0001"],
)
def test_invalid_ids(value: str) -> None:
    assert not is_evidence_id(value)


def test_constructors() -> None:
    assert rule_evidence_id("win_powershell_encoded_command") == "rule-win_powershell_encoded_command"
    assert technique_evidence_id("T1059.001") == "attack-T1059.001"


def test_evidence_id_type_validates_in_models() -> None:
    class M(BaseModel):
        ref: EvidenceId

    assert M(ref="ev-0007").ref == "ev-0007"
    with pytest.raises(ValidationError):
        M(ref="nope")
