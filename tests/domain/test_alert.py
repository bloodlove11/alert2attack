import pytest
from pydantic import ValidationError

from alert2attack.domain.alert import Alert, Severity


def test_alert_roundtrip() -> None:
    a = Alert.model_validate(
        {
            "alert_id": "alr-0001",
            "host": "WS-FIN-07",
            "fired_at": "2024-03-12T10:02:14Z",
            "rule_id": "win_powershell_encoded_command",
            "rule_title": "Suspicious Encoded PowerShell Command Line",
            "severity": "high",
            "trigger_event_id": "ev-0004",
        }
    )
    assert a.severity is Severity.HIGH
    assert a.model_dump(mode="json")["fired_at"] == "2024-03-12T10:02:14Z"


def test_alert_requires_valid_trigger_id() -> None:
    with pytest.raises(ValidationError):
        Alert(
            alert_id="a",
            host="h",
            fired_at="2024-03-12T10:02:14Z",  # type: ignore[arg-type]
            rule_id="r",
            rule_title="t",
            severity=Severity.LOW,
            trigger_event_id="event-4",
        )
