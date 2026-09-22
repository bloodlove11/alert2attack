"""Investigation trace: LLM turns + tool-call ledger snapshot."""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import Any

from pydantic import BaseModel, Field

from alert2attack.agent.llm import ChatMessage, ChatResponse, assistant_message, to_openai_messages
from alert2attack.tools.context import ToolCallRecord

_SECRET_ENV_KEYS = ("EXPLABS_API_KEY", "OPENAI_API_KEY")


def redact_secrets(text: str) -> str:
    """Omit live API keys from persisted traces / distill JSONL."""
    out = text
    for name in _SECRET_ENV_KEYS:
        secret = os.environ.get(name)
        if secret:
            out = out.replace(secret, "[REDACTED]")
    return out


def _redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, list):
        return [_redact_obj(v) for v in value]
    if isinstance(value, dict):
        return {k: _redact_obj(v) for k, v in value.items()}
    return value


class LlmCallRecord(BaseModel):
    seq: int
    role: str  # plan | investigate | write | repair
    model: str
    prompt_chars: int
    response_chars: int
    tool_call_count: int = 0
    duration_ms: float = 0.0
    messages: list[dict[str, Any]] = Field(default_factory=list)
    response: dict[str, Any] | None = None


def llm_call_record(
    *,
    seq: int,
    role: str,
    model: str,
    messages: Sequence[ChatMessage],
    response: ChatResponse,
    duration_ms: float,
) -> LlmCallRecord:
    prompt_chars = sum(len(m.content or "") for m in messages)
    assistant = assistant_message(response)
    return LlmCallRecord(
        seq=seq,
        role=role,
        model=model,
        prompt_chars=prompt_chars,
        response_chars=len(response.content or "") + sum(len(tc.name) for tc in response.tool_calls),
        tool_call_count=len(response.tool_calls),
        duration_ms=duration_ms,
        messages=_redact_obj(to_openai_messages(messages)),
        response=_redact_obj(to_openai_messages([assistant])[0]),
    )


class Trace(BaseModel):
    case_id: str
    model: str
    llm_calls: list[LlmCallRecord] = Field(default_factory=list)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    budget: dict[str, Any] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)

    def add_llm(self, record: LlmCallRecord) -> None:
        self.llm_calls.append(record)

    def add_note(self, note: str) -> None:
        self.notes.append(note)
