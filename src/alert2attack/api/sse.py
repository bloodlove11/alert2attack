"""Server-sent events for a running investigation.

SSE rather than WebSocket: the flow is one-directional, EventSource reconnects
on its own, it is plain HTTP through any proxy, and it needs no new dependency.
A bidirectional channel would buy nothing this feature uses.

The stream carries *progress*. It never carries the case file — that is fetched
over REST once ``done`` arrives, so there is exactly one authoritative
representation of a case file.
"""

from __future__ import annotations

import asyncio
import queue
from collections.abc import AsyncIterator, Awaitable, Callable

from alert2attack.agent.progress import ProgressEvent
from alert2attack.api.progress_hub import JobProgress

# How long the reader sleeps when the queue is empty. Small enough to feel live,
# large enough that an idle stream costs nothing.
POLL_SECONDS = 0.05

# Proxies and browsers drop a silent connection; a comment line keeps it open
# without being delivered to the EventSource message handler.
KEEPALIVE_SECONDS = 15.0

TERMINAL_TYPES = frozenset({"done", "error"})


def format_event(event: ProgressEvent) -> str:
    """One SSE frame. ``id:`` is the seq, which is what Last-Event-ID replays."""
    payload = event.model_dump_json()
    return f"id: {event.seq}\nevent: {event.type}\ndata: {payload}\n\n"


def parse_last_event_id(raw: str | None) -> int:
    """A malformed or absent Last-Event-ID means "from the beginning"."""
    if not raw:
        return 0
    try:
        return max(0, int(raw.strip()))
    except ValueError:
        return 0


async def event_stream(
    progress: JobProgress,
    *,
    after_seq: int = 0,
    is_disconnected: Callable[[], Awaitable[bool]] | None = None,
) -> AsyncIterator[str]:
    """Replay what was missed, then follow the live stream until it ends.

    ``is_disconnected`` is Starlette's ``Request.is_disconnected``. Without it
    the stream ends only on a terminal event or on close, which is what the
    tests want.
    """
    replay, sub = progress.subscribe(after_seq=after_seq)
    try:
        for event in replay:
            yield format_event(event)
            if event.type in TERMINAL_TYPES:
                return

        idle = 0.0
        while True:
            try:
                item: ProgressEvent | None = sub.get_nowait()
            except queue.Empty:
                if is_disconnected is not None and await is_disconnected():
                    return
                await asyncio.sleep(POLL_SECONDS)
                idle += POLL_SECONDS
                if idle >= KEEPALIVE_SECONDS:
                    idle = 0.0
                    yield ": keepalive\n\n"
                continue

            idle = 0.0
            if item is None:  # sentinel: the job closed without a terminal event
                return
            yield format_event(item)
            if item.type in TERMINAL_TYPES:
                return
    finally:
        progress.unsubscribe(sub)
