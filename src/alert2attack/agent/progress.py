"""Live progress events from a running investigation.

The agent already records everything it did — but only in the ``Trace``, and only
once the run has finished. That is fine for evaluation and useless for watching.
This module adds a side channel that emits the same facts as they happen.

The agent knows nothing about HTTP. It holds a ``ProgressEmitter`` whose sink
defaults to ``NullSink``, so the CLI, the eval runner and every existing test
take a code path that allocates a few objects and drops them. Only the API
installs a sink that goes anywhere.

Events are built from the same records that populate the trace, so the two
cannot describe different runs.
"""

from __future__ import annotations

import threading
from time import perf_counter
from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from alert2attack.agent.trace import LlmCallRecord
from alert2attack.tools.context import ToolCallRecord
from alert2attack.verify.models import VerificationReport

Phase = Literal["plan", "investigate", "write", "verify", "repair", "levers"]
EvidenceKind = Literal["event", "sigma_rule", "attack_technique"]


class _Event(BaseModel):
    # Mutable: seq and elapsed_ms are stamped by the emitter, not the call site.
    model_config = ConfigDict(extra="forbid")

    seq: int = 0
    elapsed_ms: float = 0.0


class PhaseEvent(_Event):
    type: Literal["phase"] = "phase"
    phase: Phase
    status: Literal["start", "end"] = "start"


class ToolCallEvent(_Event):
    type: Literal["tool_call"] = "tool_call"
    call_seq: int
    tool: str
    args_digest: str
    ok: bool
    evidence_ids: list[str]
    duration_ms: float
    error: str | None = None


class LlmCallEvent(_Event):
    type: Literal["llm_call"] = "llm_call"
    call_seq: int
    role: str
    model: str
    prompt_chars: int
    response_chars: int
    tool_call_count: int
    duration_ms: float


class LedgerEvent(_Event):
    type: Literal["ledger"] = "ledger"
    evidence_id: str
    kind: EvidenceKind


class LeverEvent(_Event):
    """A deterministic post-write control. ``fired`` false is still informative:
    it shows the lever was considered and declined, which a note never recorded."""

    type: Literal["lever"] = "lever"
    lever_id: str
    fired: bool
    effect: str | None = None


class VerifyEvent(_Event):
    type: Literal["verify"] = "verify"
    status: str
    passed: bool
    error_codes: list[str]
    stripped_claims: int
    repairs_used: int


class DoneEvent(_Event):
    type: Literal["done"] = "done"
    job_id: str | None = None


class ErrorEvent(_Event):
    type: Literal["error"] = "error"
    message: str


ProgressEvent = Annotated[
    PhaseEvent | ToolCallEvent | LlmCallEvent | LedgerEvent | LeverEvent | VerifyEvent | DoneEvent | ErrorEvent,
    Field(discriminator="type"),
]


def evidence_kind(evidence_id: str) -> EvidenceKind:
    if evidence_id.startswith("ev-"):
        return "event"
    if evidence_id.startswith("rule-"):
        return "sigma_rule"
    return "attack_technique"


def _digest(args: dict[str, object], *, limit: int = 120) -> str:
    """A short, human-readable rendering of tool arguments.

    Not the full arguments: this crosses a network boundary to a browser on
    every tool call, and the console shows it in a one-line log row.
    """
    if not args:
        return ""
    rendered = ", ".join(f"{k}={v!r}" for k, v in sorted(args.items()))
    return rendered if len(rendered) <= limit else rendered[: limit - 1] + "…"


class ProgressSink(Protocol):
    def emit(self, event: ProgressEvent) -> None: ...


class NullSink:
    """The default. Every non-API caller takes this path."""

    def emit(self, event: ProgressEvent) -> None:
        return None


class RecordingSink:
    """Collects events in order. For tests and the replay fixture."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.events: list[ProgressEvent] = []

    def emit(self, event: ProgressEvent) -> None:
        with self._lock:
            self.events.append(event)

    def types(self) -> list[str]:
        with self._lock:
            return [e.type for e in self.events]


class ProgressEmitter:
    """Stamps ordering onto events and hands them to a sink.

    Sequence numbers are assigned here rather than at call sites so they are
    monotonic across every event type — which is what lets a reconnecting client
    say "resume after 41" and get a coherent stream.
    """

    def __init__(self, sink: ProgressSink | None = None) -> None:
        self._sink: ProgressSink = sink or NullSink()
        self._lock = threading.Lock()
        self._seq = 0
        self._started = perf_counter()

    def _emit(self, event: ProgressEvent) -> None:
        with self._lock:
            self._seq += 1
            event.seq = self._seq
        event.elapsed_ms = (perf_counter() - self._started) * 1000.0
        self._sink.emit(event)

    # -- call sites ------------------------------------------------------------

    def phase(self, phase: Phase, status: Literal["start", "end"] = "start") -> None:
        self._emit(PhaseEvent(phase=phase, status=status))

    def tool_call(self, record: ToolCallRecord) -> None:
        self._emit(
            ToolCallEvent(
                call_seq=record.seq,
                tool=record.tool,
                args_digest=_digest(dict(record.args)),
                ok=record.ok,
                evidence_ids=list(record.evidence_ids),
                duration_ms=record.duration_ms,
                error=record.error,
            )
        )
        # A citation only becomes available because a tool returned it.
        for evidence_id in record.evidence_ids:
            self._emit(LedgerEvent(evidence_id=evidence_id, kind=evidence_kind(evidence_id)))

    def llm_call(self, record: LlmCallRecord) -> None:
        self._emit(
            LlmCallEvent(
                call_seq=record.seq,
                role=record.role,
                model=record.model,
                prompt_chars=record.prompt_chars,
                response_chars=record.response_chars,
                tool_call_count=record.tool_call_count,
                duration_ms=record.duration_ms,
            )
        )

    def lever(self, lever_id: str, *, fired: bool, effect: str | None = None) -> None:
        self._emit(LeverEvent(lever_id=lever_id, fired=fired, effect=effect))

    def verification(self, report: VerificationReport) -> None:
        self._emit(
            VerifyEvent(
                status=report.status,
                passed=report.passed,
                error_codes=[e.code for e in report.errors],
                stripped_claims=report.stripped_claims,
                repairs_used=report.repairs_used,
            )
        )

    def done(self, job_id: str | None = None) -> None:
        self._emit(DoneEvent(job_id=job_id))

    def error(self, message: str) -> None:
        self._emit(ErrorEvent(message=message))
