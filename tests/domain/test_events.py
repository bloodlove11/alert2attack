from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from alert2attack.domain.events import Event, EventKind


def _proc(**over: object) -> Event:
    base: dict[str, object] = {
        "event_id": "ev-0004",
        "kind": EventKind.PROCESS_CREATE,
        "ts": "2024-03-12T10:02:14Z",
        "host": "WS-FIN-07",
        "user": "CORP\\jdoe",
        "pid": 5288,
        "ppid": 4120,
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -NoP -W Hidden -Enc AAAA",
        "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "source_event_code": 1,
    }
    base.update(over)
    return Event.model_validate(base)


def test_parses_and_normalises_timestamp_to_utc() -> None:
    e = _proc()
    assert e.ts == datetime(2024, 3, 12, 10, 2, 14, tzinfo=UTC)
    assert e.ts.tzinfo is not None


def test_rejects_naive_timestamp() -> None:
    with pytest.raises(ValidationError):
        _proc(ts="2024-03-12T10:02:14")


def test_rejects_unknown_field_and_bad_id() -> None:
    with pytest.raises(ValidationError):
        _proc(bogus=1)
    with pytest.raises(ValidationError):
        _proc(event_id="4")


def test_is_frozen() -> None:
    e = _proc()
    with pytest.raises(ValidationError):
        e.pid = 1  # type: ignore[misc]


def test_search_text_is_lowercase_concatenation_of_searchable_fields() -> None:
    e = _proc()
    text = e.search_text()
    assert "winword.exe" in text
    assert "-enc aaaa" in text
    assert "corp\\jdoe" in text
    assert text == text.lower()


def test_all_nine_kinds_exist() -> None:
    assert {k.value for k in EventKind} == {
        "process_create",
        "network_connect",
        "image_load",
        "process_access",
        "file_create",
        "registry_set",
        "dns_query",
        "service_install",
        "scheduled_task",
    }
