from datetime import UTC, datetime
from pathlib import Path

from alert2attack.dataset.otrf import host_from_record, normalize_record, parse_otrf_timestamp, pid_int
from alert2attack.domain.events import EventKind

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "otrf" / "sample_sysmon.jsonl"


def _records() -> list[dict]:
    import json

    return [json.loads(line) for line in FIXTURE.read_text().splitlines() if line.strip()]


def test_pid_int_accepts_string() -> None:
    assert pid_int("2316") == 2316
    assert pid_int(None) is None


def test_parse_naive_utctime_as_utc() -> None:
    ts = parse_otrf_timestamp("2020-09-04 20:09:55.760")
    assert ts == datetime(2020, 9, 4, 20, 9, 55, 760000, tzinfo=UTC)


def test_normalize_process_create() -> None:
    raw = next(r for r in _records() if r["EventID"] == 1 and "powershell" in r["Image"].lower())
    ev = normalize_record(raw, event_id="ev-0001")
    assert ev is not None
    assert ev.kind is EventKind.PROCESS_CREATE
    assert ev.pid == 2316 and ev.ppid == 2440
    assert ev.image and ev.image.endswith("powershell.exe")
    assert ev.command_line and "-enc" in ev.command_line.lower()
    assert ev.sha256 and len(ev.sha256) == 64
    assert host_from_record(raw) == "WORKSTATION5.theshire.local"


def test_normalize_network_and_dns() -> None:
    net = normalize_record(next(r for r in _records() if r["EventID"] == 3), event_id="ev-0002")
    dns = normalize_record(next(r for r in _records() if r["EventID"] == 22), event_id="ev-0003")
    assert net is not None and net.kind is EventKind.NETWORK_CONNECT and net.dest_port == 443
    assert dns is not None and dns.kind is EventKind.DNS_QUERY and dns.query == "wdcp.microsoft.com"


def test_unknown_event_returns_none() -> None:
    assert normalize_record({"EventID": 9999, "Channel": "Security", "UtcTime": "2020-01-01 00:00:00"}) is None
