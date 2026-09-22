"""Investigation output models (CaseFile). Pure domain — no I/O."""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from alert2attack.domain.evidence import EvidenceId

MAX_SUMMARY_SENTENCES = 3
# Periods inside these tokens are not sentence boundaries (SOC writeups).
# Do not treat `.com` as a file suffix — it collides with domains.
_NON_SENTENCE_PERIODS = re.compile(
    r"(?:"
    r"T\d{4}(?:\.\d{3})?"
    r"|\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b"
    r"|\b\d+\.\d+(?:\.\d+)*\b"
    r"|[A-Za-z0-9_+-]+\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|jse|hta|sct|msi|scr|lnk|inf)"
    r")",
    re.IGNORECASE,
)


def _mask_non_sentence_periods(text: str) -> str:
    return _NON_SENTENCE_PERIODS.sub(lambda m: m.group(0).replace(".", "\u2024"), text)


def summary_sentence_count(text: str) -> int:
    """Count sentence-ending periods after masking ids, hosts, versions, and extensions."""
    return _mask_non_sentence_periods(text.strip()).count(".")


def clip_summary_sentences(text: str, *, max_sentences: int = MAX_SUMMARY_SENTENCES) -> str:
    """Keep the first ``max_sentences`` real sentences; do not invent replacement text."""
    stripped = text.strip()
    masked = _mask_non_sentence_periods(stripped)
    if masked.count(".") <= max_sentences:
        return stripped
    seen = 0
    cut_at: int | None = None
    for index, char in enumerate(masked):
        if char != ".":
            continue
        seen += 1
        if seen == max_sentences:
            cut_at = index
            break
    if cut_at is None:
        return stripped
    return stripped[: cut_at + 1].rstrip()


class Verdict(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    LIKELY_BENIGN = "likely_benign"
    NOT_ENOUGH_EVIDENCE = "not_enough_evidence"


class NextAction(StrEnum):
    ISOLATE_HOST = "isolate_host"
    KILL_PROCESS = "kill_process"
    COLLECT_SCRIPT = "collect_script"
    COLLECT_MEMORY = "collect_memory"
    BLOCK_HASH = "block_hash"
    RESET_CREDENTIALS = "reset_credentials"
    ESCALATE = "escalate"
    MONITOR = "monitor"
    CLOSE_AS_BENIGN = "close_as_benign"


class Claim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1)
    evidence: list[EvidenceId] = Field(min_length=1)


class TimelineEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ts: str
    text: str
    evidence: list[EvidenceId] = Field(min_length=1)


class TechniqueClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    evidence: list[EvidenceId] = Field(min_length=1)
    note: str = ""


class Scope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root_process: Claim | None = None
    involved_pids: list[int] = Field(default_factory=list)
    persistence: list[Claim] = Field(default_factory=list)
    beyond_process: bool = False


class ActionRecommendation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: NextAction
    rationale: Claim


class CaseFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: Verdict
    confidence: Literal["low", "medium", "high"]
    summary: str
    timeline: list[TimelineEntry] = Field(default_factory=list)
    techniques: list[TechniqueClaim] = Field(default_factory=list)
    scope: Scope = Field(default_factory=Scope)
    next_actions: list[ActionRecommendation] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)

    @field_validator("summary")
    @classmethod
    def _summary_short(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("summary must be non-empty")
        if summary_sentence_count(text) > MAX_SUMMARY_SENTENCES:
            raise ValueError("summary must be at most 3 sentences")
        return text
