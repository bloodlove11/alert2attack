from datetime import UTC, datetime

from alert2attack.dataset.window import assign_evidence_ids, box_events
from alert2attack.domain.events import Event, EventKind


def _ev(eid: str, host: str, minute: int, pid: int = 1) -> Event:
    return Event(
        event_id=eid,  # type: ignore[arg-type]
        kind=EventKind.PROCESS_CREATE,
        ts=datetime(2024, 1, 1, 12, minute, tzinfo=UTC),
        host=host,
        pid=pid,
        image="C:\\Windows\\System32\\cmd.exe",
    )


def test_box_filters_host_and_window_and_renumbers() -> None:
    events = [
        _ev("ev-0099", "HOST-A", 0),
        _ev("ev-0098", "HOST-A", 5),
        _ev("ev-0097", "HOST-B", 5),
        _ev("ev-0096", "HOST-A", 30),
    ]
    start = datetime(2024, 1, 1, 12, 0, tzinfo=UTC)
    end = datetime(2024, 1, 1, 12, 10, tzinfo=UTC)
    boxed = box_events(events, host="HOST-A", start=start, end=end)
    assert [e.event_id for e in boxed] == ["ev-0001", "ev-0002"]
    assert [e.pid for e in boxed] == [1, 1]


def test_assign_evidence_ids_sorts_by_ts() -> None:
    later = _ev("ev-0001", "H", 2, pid=2)
    earlier = _ev("ev-0002", "H", 1, pid=1)
    out = assign_evidence_ids([later, earlier])
    assert [e.event_id for e in out] == ["ev-0001", "ev-0002"]
    assert out[0].pid == 1
