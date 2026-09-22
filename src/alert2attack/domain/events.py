from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator

from alert2attack.domain.evidence import EvidenceId


class EventKind(StrEnum):
    PROCESS_CREATE = "process_create"  # Sysmon 1
    NETWORK_CONNECT = "network_connect"  # Sysmon 3
    IMAGE_LOAD = "image_load"  # Sysmon 7
    PROCESS_ACCESS = "process_access"  # Sysmon 10
    FILE_CREATE = "file_create"  # Sysmon 11
    REGISTRY_SET = "registry_set"  # Sysmon 13
    DNS_QUERY = "dns_query"  # Sysmon 22
    SERVICE_INSTALL = "service_install"  # System 7045
    SCHEDULED_TASK = "scheduled_task"  # Security 4698


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC)


class Event(BaseModel):
    """One normalized telemetry event. Flat on purpose: it is rendered to an LLM as-is."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: EvidenceId
    kind: EventKind
    ts: datetime
    host: str
    user: str | None = None
    pid: int | None = None
    ppid: int | None = None
    image: str | None = None
    command_line: str | None = None
    parent_image: str | None = None
    parent_command_line: str | None = None
    sha256: str | None = None
    target_pid: int | None = None
    target_image: str | None = None
    target_path: str | None = None
    details: str | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    dest_host: str | None = None
    query: str | None = None
    source: str = "sysmon"
    source_event_code: int | None = None

    @field_validator("ts")
    @classmethod
    def _ts_utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    def search_text(self) -> str:
        parts = (
            self.user,
            self.image,
            self.command_line,
            self.parent_image,
            self.parent_command_line,
            self.target_image,
            self.target_path,
            self.details,
            self.dest_ip,
            self.dest_host,
            self.query,
            self.sha256,
        )
        return " ".join(p for p in parts if p).lower()
