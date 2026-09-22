from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator

from alert2attack.domain.events import ensure_utc
from alert2attack.domain.evidence import EvidenceId


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Alert(BaseModel):
    """What the EDR shows the analyst when the case opens."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    alert_id: str
    host: str
    fired_at: datetime
    rule_id: str
    rule_title: str
    severity: Severity
    trigger_event_id: EvidenceId

    @field_validator("fired_at")
    @classmethod
    def _fired_at_utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)
