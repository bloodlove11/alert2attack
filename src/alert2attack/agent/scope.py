"""Grounded pid collection for the agent write/repair path."""

from __future__ import annotations

from collections.abc import Iterable

from alert2attack.domain.scope import pids_from_events
from alert2attack.store.case_store import CaseStore


def known_pids_from_store(
    store: CaseStore,
    case_id: str,
    ledger_ids: Iterable[str],
) -> list[int]:
    """Pids grounded in the alert trigger and in ledger-backed store events.

    Sources, in stable order:
    - ``trigger_event.pid`` and ``trigger_event.target_pid`` when set
    - ``pid`` / ``ppid`` / ``target_pid`` from store events whose ``event_id``
      is already in the evidence ledger (sorted by id)
    """
    seen: set[int] = set()
    out: list[int] = []

    alert = store.get_alert(case_id)
    trigger = store.get_event(case_id, alert.trigger_event_id)
    if trigger is not None:
        for pid in (trigger.pid, trigger.target_pid):
            if pid is None or pid in seen:
                continue
            seen.add(pid)
            out.append(pid)

    ledger_events = []
    for event_id in sorted(ledger_ids):
        event = store.get_event(case_id, event_id)
        if event is not None:
            ledger_events.append(event)
    for pid in pids_from_events(ledger_events):
        if pid in seen:
            continue
        seen.add(pid)
        out.append(pid)
    return out
