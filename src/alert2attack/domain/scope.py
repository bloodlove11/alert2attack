"""Scope helpers. Pure domain — no I/O."""

from __future__ import annotations

from collections.abc import Iterable

from alert2attack.domain.casefile import CaseFile
from alert2attack.domain.events import Event


def pids_from_events(events: Iterable[Event]) -> list[int]:
    """Stable, de-duplicated pid / ppid / target_pid values present on events."""
    seen: set[int] = set()
    out: list[int] = []
    for event in events:
        for pid in (event.pid, event.ppid, event.target_pid):
            if pid is None or pid in seen:
                continue
            seen.add(pid)
            out.append(pid)
    return out


def hydrate_involved_pids(case_file: CaseFile, known_pids: Iterable[int]) -> CaseFile:
    """Union grounded ``known_pids`` into ``scope.involved_pids``.

    Existing model pids are kept (even if they are not in ``known_pids``). New
    pids are appended in ``known_pids`` order, de-duplicated. Does not invent
    pids and does not create ``root_process`` (that still needs a Claim + evidence).
    """
    seen: set[int] = set()
    merged: list[int] = []
    for pid in (*case_file.scope.involved_pids, *known_pids):
        if pid in seen:
            continue
        seen.add(pid)
        merged.append(pid)
    if merged == list(case_file.scope.involved_pids):
        return case_file
    return case_file.model_copy(
        update={"scope": case_file.scope.model_copy(update={"involved_pids": merged})}
    )
