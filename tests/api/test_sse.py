"""Progress fan-out and the SSE stream."""

from __future__ import annotations

import json
import threading

import pytest
from fastapi.testclient import TestClient

from alert2attack.agent.progress import DoneEvent, ErrorEvent, PhaseEvent, ToolCallEvent
from alert2attack.api.app import create_app
from alert2attack.api.factory import ChatFactory
from alert2attack.api.progress_hub import JobProgress, ProgressHub
from alert2attack.api.sse import format_event, parse_last_event_id

SCENARIO = "otrf_empire_launcher_vbs"


def _phase(phase: str = "plan") -> PhaseEvent:
    return PhaseEvent(phase=phase)  # type: ignore[arg-type]


# -- the hub ------------------------------------------------------------------


def test_emit_stamps_a_monotonic_wire_sequence() -> None:
    """The API also emits (done/error), so the hub owns the wire sequence."""
    progress = JobProgress()
    for _ in range(3):
        progress.emit(_phase())
    progress.emit(DoneEvent(job_id="j"))
    assert [e.seq for e in progress.buffered()] == [1, 2, 3, 4]


def test_subscriber_receives_live_events() -> None:
    progress = JobProgress()
    _, sub = progress.subscribe()
    progress.emit(_phase("investigate"))
    received = sub.get_nowait()
    assert received is not None and received.type == "phase"


def test_subscribe_replays_what_was_missed() -> None:
    progress = JobProgress()
    for _ in range(5):
        progress.emit(_phase())

    replay, _ = progress.subscribe(after_seq=3)
    assert [e.seq for e in replay] == [4, 5]


def test_subscribe_after_everything_replays_nothing() -> None:
    progress = JobProgress()
    progress.emit(_phase())
    replay, _ = progress.subscribe(after_seq=99)
    assert replay == []


def test_events_are_not_delivered_twice_across_replay_and_live() -> None:
    """Replay and subscription are taken under one lock for exactly this."""
    progress = JobProgress()
    progress.emit(_phase())
    replay, sub = progress.subscribe(after_seq=0)
    progress.emit(_phase())

    seen = [e.seq for e in replay]
    while not sub.empty():
        item = sub.get_nowait()
        if item is not None:
            seen.append(item.seq)
    assert seen == sorted(set(seen)), "an event was delivered twice"
    assert seen == [1, 2]


def test_buffer_is_bounded() -> None:
    progress = JobProgress(maxlen=10)
    for _ in range(25):
        progress.emit(_phase())
    buffered = progress.buffered()
    assert len(buffered) == 10
    assert buffered[-1].seq == 25, "the newest events are the ones kept"


def test_close_wakes_subscribers_with_a_sentinel() -> None:
    progress = JobProgress()
    _, sub = progress.subscribe()
    progress.close()
    assert sub.get_nowait() is None


def test_emit_after_close_is_dropped() -> None:
    progress = JobProgress()
    progress.close()
    progress.emit(_phase())
    assert progress.buffered() == []


def test_subscribing_to_a_closed_job_still_terminates() -> None:
    progress = JobProgress()
    progress.emit(_phase())
    progress.close()
    replay, sub = progress.subscribe()
    assert [e.seq for e in replay] == [1]
    assert sub.get_nowait() is None


def test_unsubscribe_stops_delivery() -> None:
    progress = JobProgress()
    _, sub = progress.subscribe()
    progress.unsubscribe(sub)
    progress.emit(_phase())
    assert sub.empty()


def test_hub_evicts_and_closes_the_oldest_job() -> None:
    hub = ProgressHub(max_jobs=2)
    first = hub.create("a")
    hub.create("b")
    hub.create("c")
    assert hub.get("a") is None, "oldest job evicted"
    assert first.closed, "an evicted job is closed so its subscribers wake"
    assert hub.get("c") is not None


def test_concurrent_emit_keeps_the_sequence_dense() -> None:
    """The run thread emits while the reader thread subscribes."""
    progress = JobProgress(maxlen=1000)

    def emit_many() -> None:
        for _ in range(100):
            progress.emit(_phase())

    threads = [threading.Thread(target=emit_many) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    seqs = sorted(e.seq for e in progress.buffered())
    assert seqs == list(range(1, 401))


# -- framing ------------------------------------------------------------------


def test_format_event_is_a_valid_sse_frame() -> None:
    event = ToolCallEvent(
        call_seq=1, tool="get_alert", args_digest="", ok=True, evidence_ids=["ev-0001"], duration_ms=1.5
    )
    event.seq = 7
    frame = format_event(event)

    assert frame.startswith("id: 7\n")
    assert "event: tool_call\n" in frame
    assert frame.endswith("\n\n")
    data = json.loads(frame.split("data: ", 1)[1].strip())
    assert data["tool"] == "get_alert"
    assert data["evidence_ids"] == ["ev-0001"]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(None, 0), ("", 0), ("12", 12), ("  12  ", 12), ("-4", 0), ("abc", 0), ("1.5", 0)],
)
def test_last_event_id_parsing_never_raises(raw: str | None, expected: int) -> None:
    assert parse_last_event_id(raw) == expected


# -- the route ----------------------------------------------------------------


@pytest.fixture
def client(scripted_factory: ChatFactory) -> TestClient:
    return TestClient(create_app(chat_factory=scripted_factory))


def _frames(text: str) -> list[dict[str, str]]:
    frames = []
    for block in text.split("\n\n"):
        if not block.strip() or block.startswith(":"):
            continue
        fields: dict[str, str] = {}
        for line in block.splitlines():
            key, _, value = line.partition(": ")
            fields[key] = value
        frames.append(fields)
    return frames


def test_stream_replays_a_finished_run(client: TestClient) -> None:
    """A sync investigation is over before the stream opens, so everything the
    client sees comes from the replay buffer."""
    job = client.post(
        "/investigations",
        json={"scenario_id": SCENARIO, "model": "scripted", "sync": True},
    ).json()

    with client.stream("GET", f"/investigations/{job['id']}/events") as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        frames = _frames(resp.read().decode())

    types = [f["event"] for f in frames]
    assert types[0] == "phase"
    assert "tool_call" in types
    assert "llm_call" in types
    assert "lever" in types
    assert types[-1] == "done", "the stream must terminate on done"


def test_stream_ids_are_dense_and_ordered(client: TestClient) -> None:
    job = client.post(
        "/investigations",
        json={"scenario_id": SCENARIO, "model": "scripted", "sync": True},
    ).json()
    with client.stream("GET", f"/investigations/{job['id']}/events") as resp:
        frames = _frames(resp.read().decode())

    ids = [int(f["id"]) for f in frames]
    assert ids == list(range(1, len(ids) + 1))


def test_last_event_id_resumes_after_the_given_seq(client: TestClient) -> None:
    job = client.post(
        "/investigations",
        json={"scenario_id": SCENARIO, "model": "scripted", "sync": True},
    ).json()

    with client.stream("GET", f"/investigations/{job['id']}/events") as resp:
        everything = _frames(resp.read().decode())

    resume_after = int(everything[2]["id"])
    with client.stream(
        "GET",
        f"/investigations/{job['id']}/events",
        headers={"Last-Event-ID": str(resume_after)},
    ) as resp:
        resumed = _frames(resp.read().decode())

    assert [int(f["id"]) for f in resumed] == [int(f["id"]) for f in everything[3:]]


def test_done_event_carries_the_job_id_but_no_case_file(client: TestClient) -> None:
    """The stream is progress. The case file is fetched over REST."""
    job = client.post(
        "/investigations",
        json={"scenario_id": SCENARIO, "model": "scripted", "sync": True},
    ).json()
    with client.stream("GET", f"/investigations/{job['id']}/events") as resp:
        frames = _frames(resp.read().decode())

    done = json.loads(frames[-1]["data"])
    assert done["job_id"] == job["id"]
    assert "case_file" not in done


def test_stream_carries_no_gold(client: TestClient) -> None:
    job = client.post(
        "/investigations",
        json={"scenario_id": SCENARIO, "model": "scripted", "sync": True},
    ).json()
    with client.stream("GET", f"/investigations/{job['id']}/events") as resp:
        body = resp.read().decode()
    for marker in ("GOLD-MARKER", "key_pids", "acceptable_actions", "narrative"):
        assert marker not in body


def test_stream_for_unknown_job_is_404(client: TestClient) -> None:
    with client.stream("GET", "/investigations/no-such-job/events") as resp:
        assert resp.status_code == 404


def test_stream_for_a_job_without_live_progress_is_409(scripted_factory: ChatFactory) -> None:
    """The job store outlives the hub; a result is still available over REST."""
    app = create_app(chat_factory=scripted_factory)
    with TestClient(app) as c:
        job = c.post(
            "/investigations",
            json={"scenario_id": SCENARIO, "model": "scripted", "sync": True},
        ).json()
        app.state.progress_hub._jobs.clear()
        with c.stream("GET", f"/investigations/{job['id']}/events") as resp:
            assert resp.status_code == 409


def test_error_event_terminates_the_stream() -> None:
    progress = JobProgress()
    progress.emit(ErrorEvent(message="ollama unreachable"))
    replay, _ = progress.subscribe()
    assert replay[0].type == "error"
