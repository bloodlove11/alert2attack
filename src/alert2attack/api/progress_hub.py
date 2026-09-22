"""Per-job progress fan-out: a replay buffer plus live subscriber queues.

The investigation runs in FastAPI's threadpool while the SSE response is driven
by the event loop, so this crosses a thread boundary. It uses ``queue.Queue``
and a short poll on the reader side rather than ``asyncio.Queue`` with
``call_soon_threadsafe``: at one to three viewers the polling cost is nil, and
the resulting code has no captured event loop to get wrong.

Events are buffered so a client that reconnects can say "resume after 41"
(``Last-Event-ID``) and receive what it missed. Past the buffer the client
refetches state over REST instead — degradation, not failure.
"""

from __future__ import annotations

import queue
import threading
from collections import deque

from alert2attack.agent.progress import ProgressEvent

# Roughly a long investigation's worth of events. A reconnect that falls
# further behind than this is better served by a REST refetch.
DEFAULT_BUFFER = 500


class JobProgress:
    """One job's event stream. Satisfies ProgressSink."""

    def __init__(self, *, maxlen: int = DEFAULT_BUFFER) -> None:
        self._lock = threading.Lock()
        self._buffer: deque[ProgressEvent] = deque(maxlen=maxlen)
        self._subscribers: list[queue.Queue[ProgressEvent | None]] = []
        self._closed = False
        self._seq = 0

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def emit(self, event: ProgressEvent) -> None:
        """Stamp the wire sequence and fan out.

        Sequence is assigned here, not by the agent's emitter, because the API
        also emits (``done``, ``error``) and a client resuming by Last-Event-ID
        needs one monotonic sequence over everything that crossed the wire —
        not two interleaved ones.
        """
        with self._lock:
            if self._closed:
                return
            self._seq += 1
            event.seq = self._seq
            self._buffer.append(event)
            subscribers = list(self._subscribers)
        for sub in subscribers:
            sub.put(event)

    def close(self) -> None:
        """No more events. Wakes every subscriber with a sentinel."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            subscribers = list(self._subscribers)
        for sub in subscribers:
            sub.put(None)

    def subscribe(
        self, *, after_seq: int = 0
    ) -> tuple[list[ProgressEvent], queue.Queue[ProgressEvent | None]]:
        """Return everything already buffered after ``after_seq``, plus a live queue.

        Both are taken under one lock so an event emitted mid-subscribe lands in
        exactly one of them and is neither dropped nor delivered twice.
        """
        sub: queue.Queue[ProgressEvent | None] = queue.Queue()
        with self._lock:
            replay = [e for e in self._buffer if e.seq > after_seq]
            self._subscribers.append(sub)
            if self._closed:
                sub.put(None)
        return replay, sub

    def unsubscribe(self, sub: queue.Queue[ProgressEvent | None]) -> None:
        with self._lock:
            if sub in self._subscribers:
                self._subscribers.remove(sub)

    def buffered(self) -> list[ProgressEvent]:
        with self._lock:
            return list(self._buffer)

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)


class ProgressHub:
    """Job id -> JobProgress, with a cap so a long-lived process cannot grow
    without bound. Evicting a finished job's buffer only costs a late viewer
    the replay; the case file itself lives in the job store."""

    def __init__(self, *, max_jobs: int = 64) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, JobProgress] = {}
        self._order: deque[str] = deque()
        self._max_jobs = max_jobs

    def create(self, job_id: str) -> JobProgress:
        progress = JobProgress()
        evicted: list[JobProgress] = []
        with self._lock:
            self._jobs[job_id] = progress
            self._order.append(job_id)
            while len(self._order) > self._max_jobs:
                stale_id = self._order.popleft()
                stale = self._jobs.pop(stale_id, None)
                if stale is not None:
                    evicted.append(stale)
        # Close outside the lock: close() takes JobProgress's own lock and
        # wakes subscribers, neither of which should happen under ours.
        for stale in evicted:
            stale.close()
        return progress

    def get(self, job_id: str) -> JobProgress | None:
        with self._lock:
            return self._jobs.get(job_id)

    def close(self, job_id: str) -> None:
        progress = self.get(job_id)
        if progress is not None:
            progress.close()
