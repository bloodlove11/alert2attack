"""Normalize OTRF / Mordor nxlog-style host JSON records into domain Events."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from alert2attack.domain.events import Event, EventKind

_SYSMON = "Microsoft-Windows-Sysmon/Operational"
_SECURITY = "Security"
_SYSTEM = "System"

# (Channel substring or exact, EventID) → EventKind. Channel match is case-insensitive contains for System.
_KIND_BY_CHANNEL_EVENT: dict[tuple[str, int], EventKind] = {
    (_SYSMON, 1): EventKind.PROCESS_CREATE,
    (_SYSMON, 3): EventKind.NETWORK_CONNECT,
    (_SYSMON, 7): EventKind.IMAGE_LOAD,
    (_SYSMON, 10): EventKind.PROCESS_ACCESS,
    (_SYSMON, 11): EventKind.FILE_CREATE,
    (_SYSMON, 13): EventKind.REGISTRY_SET,
    (_SYSMON, 22): EventKind.DNS_QUERY,
    (_SYSTEM, 7045): EventKind.SERVICE_INSTALL,
    (_SECURITY, 4698): EventKind.SCHEDULED_TASK,
}

_SHA256_RE = re.compile(r"SHA256=([A-Fa-f0-9]{64})")


def host_from_record(raw: dict[str, Any]) -> str:
    for key in ("Computer", "Hostname", "host"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "UNKNOWN"


def pid_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def parse_otrf_timestamp(value: str) -> datetime:
    """Parse OTRF UtcTime / EventTime / @timestamp into timezone-aware UTC."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # "2020-09-04 20:09:55.760" (naive) → treat as UTC
    if "T" not in text and " " in text and "+" not in text:
        text = text.replace(" ", "T") + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _extract_sha256(hashes: str | None) -> str | None:
    if not hashes:
        return None
    m = _SHA256_RE.search(hashes)
    return m.group(1).lower() if m else None


def _kind_for(raw: dict[str, Any]) -> EventKind | None:
    channel = str(raw.get("Channel") or "")
    try:
        event_id = int(raw["EventID"])
    except (TypeError, ValueError, KeyError):
        return None
    for ch, eid in _KIND_BY_CHANNEL_EVENT:
        if eid != event_id:
            continue
        if ch == _SYSTEM:
            if "System" in channel or raw.get("SourceName") == "Service Control Manager":
                return _KIND_BY_CHANNEL_EVENT[(ch, eid)]
        elif channel == ch or channel.endswith(ch.split("/")[-1]):
            return _KIND_BY_CHANNEL_EVENT[(ch, eid)]
    # Sysmon channel variants
    if "Sysmon" in channel and event_id in {1, 3, 7, 10, 11, 13, 22}:
        return _KIND_BY_CHANNEL_EVENT[(_SYSMON, event_id)]
    return None


def normalize_record(raw: dict[str, Any], *, event_id: str = "ev-0000") -> Event | None:
    """Map one OTRF flat record to an Event, or None if the kind is unsupported."""
    kind = _kind_for(raw)
    if kind is None:
        return None
    ts_raw = raw.get("UtcTime") or raw.get("@timestamp") or raw.get("EventTime")
    if not isinstance(ts_raw, str):
        return None
    try:
        ts = parse_otrf_timestamp(ts_raw)
    except ValueError:
        return None

    image = raw.get("Image") or raw.get("SourceImage")
    target_path = raw.get("TargetFilename") or raw.get("TargetObject") or raw.get("ImageLoaded")
    details = raw.get("Details") or raw.get("GrantedAccess") or raw.get("ServiceName")
    if kind is EventKind.SERVICE_INSTALL:
        details = raw.get("ServiceName") or raw.get("ImagePath") or raw.get("Message")
    if kind is EventKind.SCHEDULED_TASK:
        details = raw.get("TaskName") or raw.get("Message")

    dest_host = raw.get("DestinationHostname")
    if dest_host in (None, "", "-"):
        dest_host = None

    return Event(
        event_id=event_id,
        kind=kind,
        ts=ts,
        host=host_from_record(raw),
        user=raw.get("User") or raw.get("AccountName"),
        pid=pid_int(raw.get("ProcessId") or raw.get("SourceProcessId")),
        ppid=pid_int(raw.get("ParentProcessId")),
        image=image,
        command_line=raw.get("CommandLine"),
        parent_image=raw.get("ParentImage"),
        parent_command_line=raw.get("ParentCommandLine"),
        sha256=_extract_sha256(raw.get("Hashes")),
        target_pid=pid_int(raw.get("TargetProcessId")),
        target_image=raw.get("TargetImage"),
        target_path=target_path,
        details=str(details) if details is not None else None,
        dest_ip=raw.get("DestinationIp"),
        dest_port=pid_int(raw.get("DestinationPort")),
        dest_host=dest_host,
        query=raw.get("QueryName"),
        source="sysmon" if "Sysmon" in str(raw.get("Channel") or "") else "windows",
        source_event_code=int(raw["EventID"]) if raw.get("EventID") is not None else None,
    )


def iter_normalized(records: list[dict[str, Any]]) -> list[Event]:
    """Normalize many records; temporary ids overwritten by window.assign_evidence_ids."""
    out: list[Event] = []
    for i, raw in enumerate(records, start=1):
        ev = normalize_record(raw, event_id=f"ev-{i:04d}")
        if ev is not None:
            out.append(ev)
    return out
