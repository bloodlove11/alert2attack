"""Box telemetry to one host and time window; assign stable evidence ids."""

from __future__ import annotations

from datetime import datetime

from alert2attack.domain.events import Event


def assign_evidence_ids(events: list[Event]) -> list[Event]:
    ordered = sorted(events, key=lambda e: (e.ts, e.kind.value, e.pid or -1))
    return [e.model_copy(update={"event_id": f"ev-{i:04d}"}) for i, e in enumerate(ordered, start=1)]


def box_events(
    events: list[Event],
    *,
    host: str,
    start: datetime,
    end: datetime,
) -> list[Event]:
    """Keep events on ``host`` inside ``[start, end]``, sort, assign ``ev-NNNN``."""
    host_l = host.lower()
    kept = [e for e in events if e.host.lower() == host_l and start <= e.ts <= end]
    return assign_evidence_ids(kept)
