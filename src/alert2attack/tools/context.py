"""Shared tool plumbing: results, call records, the evidence ledger, the context handle."""

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field

from alert2attack.knowledge.base import KnowledgeBase
from alert2attack.store.case_store import CaseStore


class ToolResult(BaseModel):
    ok: bool = True
    data: Any = None
    evidence_ids: list[str] = Field(default_factory=list)
    truncated: bool = False
    error: str | None = None

    @classmethod
    def fail(cls, message: str) -> "ToolResult":
        return cls(ok=False, error=message)


class ToolCallRecord(BaseModel):
    seq: int
    tool: str
    args: dict[str, Any]
    ok: bool
    evidence_ids: list[str]
    error: str | None
    duration_ms: float


@dataclass
class EvidenceLedger:
    """Every evidence id the agent has actually been shown in this run, and how it got it."""

    calls: list[ToolCallRecord] = field(default_factory=list)
    _first_seen: dict[str, int] = field(default_factory=dict)

    def record(self, record: ToolCallRecord) -> None:
        self.calls.append(record)
        for eid in record.evidence_ids:
            self._first_seen.setdefault(eid, record.seq)

    def has(self, evidence_id: str) -> bool:
        return evidence_id in self._first_seen

    def ids(self) -> frozenset[str]:
        return frozenset(self._first_seen)

    def first_seen(self, evidence_id: str) -> int | None:
        return self._first_seen.get(evidence_id)


@dataclass(frozen=True)
class ToolContext:
    store: CaseStore
    case_id: str
    ledger: EvidenceLedger
    knowledge: KnowledgeBase
