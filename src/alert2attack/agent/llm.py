"""ChatModel protocol and implementations (Scripted / Ollama / OpenAI teacher)."""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

from openai import OpenAI

Role = Literal["system", "user", "assistant", "tool"]

DEFAULT_OLLAMA_MODEL = "qwen2.5:7b-instruct"
DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434/v1"


@dataclass(frozen=True)
class ToolCallRequest:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class ChatMessage:
    role: Role
    content: str | None = None
    tool_calls: tuple[ToolCallRequest, ...] = ()
    tool_call_id: str | None = None
    name: str | None = None


@dataclass(frozen=True)
class ChatResponse:
    content: str | None = None
    tool_calls: tuple[ToolCallRequest, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class ChatModel(Protocol):
    @property
    def model_name(self) -> str: ...

    def complete(
        self,
        messages: Sequence[ChatMessage],
        *,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
    ) -> ChatResponse: ...


def to_openai_messages(messages: Sequence[ChatMessage]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in messages:
        item: dict[str, Any] = {"role": m.role}
        if m.content is not None:
            item["content"] = m.content
        if m.tool_calls:
            item["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                }
                for tc in m.tool_calls
            ]
        if m.tool_call_id is not None:
            item["tool_call_id"] = m.tool_call_id
        if m.name is not None:
            item["name"] = m.name
        out.append(item)
    return out


def assistant_message(response: ChatResponse) -> ChatMessage:
    return ChatMessage(role="assistant", content=response.content, tool_calls=response.tool_calls)


def _parse_tool_calls(raw_calls: Any) -> tuple[ToolCallRequest, ...]:
    if not raw_calls:
        return ()
    parsed: list[ToolCallRequest] = []
    for tc in raw_calls:
        fn = tc.function
        try:
            args = json.loads(fn.arguments or "{}")
        except json.JSONDecodeError:
            args = {}
        if not isinstance(args, dict):
            args = {}
        parsed.append(ToolCallRequest(id=tc.id, name=fn.name, arguments=args))
    return tuple(parsed)


def scripted_responses_from_json(path: Path) -> list[ChatResponse]:
    """Load ScriptedChat fixtures: a JSON list of {content, tool_calls} objects."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    responses: list[ChatResponse] = []
    for item in raw:
        tool_calls = tuple(
            ToolCallRequest(
                id=tc.get("id", f"call_{i}"),
                name=tc["name"],
                arguments=tc.get("arguments", {}),
            )
            for i, tc in enumerate(item.get("tool_calls") or [])
        )
        responses.append(ChatResponse(content=item.get("content"), tool_calls=tool_calls))
    return responses


class ScriptedChat:
    """Deterministic queue of responses for tests/CI (no network)."""

    def __init__(self, responses: Sequence[ChatResponse], *, model_name: str = "scripted") -> None:
        self._responses = list(responses)
        self._model_name = model_name
        self.calls: list[list[ChatMessage]] = []

    @property
    def model_name(self) -> str:
        return self._model_name

    def complete(
        self,
        messages: Sequence[ChatMessage],
        *,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
    ) -> ChatResponse:
        del tools, tool_choice
        self.calls.append(list(messages))
        if not self._responses:
            raise RuntimeError("ScriptedChat: no responses left")
        return self._responses.pop(0)


class OpenAICompatibleChat:
    """OpenAI SDK client pointed at any compatible base URL (Ollama or cloud)."""

    def __init__(
        self,
        *,
        model: str,
        base_url: str,
        api_key: str = "ollama",
        temperature: float = 0.0,
    ) -> None:
        self._model = model
        # Remote Ollama (Lightning proxy) can exceed the SDK's 10-minute default on a long write.
        timeout = float(os.environ.get("ALERT2ATTACK_LLM_TIMEOUT_S", "1800"))
        self._client = OpenAI(base_url=base_url, api_key=api_key, timeout=timeout)
        self._temperature = temperature

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def base_url(self) -> str:
        return str(self._client.base_url)

    def complete(
        self,
        messages: Sequence[ChatMessage],
        *,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
    ) -> ChatResponse:
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": to_openai_messages(messages),
            "temperature": self._temperature,
        }
        if tools:
            kwargs["tools"] = tools
            if tool_choice is not None:
                kwargs["tool_choice"] = tool_choice
        completion = self._client.chat.completions.create(**kwargs)
        msg = completion.choices[0].message
        return ChatResponse(
            content=msg.content,
            tool_calls=_parse_tool_calls(msg.tool_calls),
            raw=completion.model_dump(),
        )


def OllamaChat(
    *,
    model: str = DEFAULT_OLLAMA_MODEL,
    base_url: str = DEFAULT_OLLAMA_BASE_URL,
) -> OpenAICompatibleChat:
    return OpenAICompatibleChat(model=model, base_url=base_url, api_key="ollama")


def ollama_from_env(*, model: str | None = None, base_url: str | None = None) -> OpenAICompatibleChat:
    """Ollama chat from the environment, with explicit arguments winning.

    The single reader of both variables. The CLI used to honour only the model
    tag, so pointing ``ALERT2ATTACK_OLLAMA_BASE_URL`` at a remote host silently
    ran against localhost instead.
    """
    return OllamaChat(
        model=model or os.environ.get("ALERT2ATTACK_OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL),
        base_url=base_url or os.environ.get("ALERT2ATTACK_OLLAMA_BASE_URL", DEFAULT_OLLAMA_BASE_URL),
    )


def OpenAIChat(
    *,
    model: str = "gpt-4o-mini",
    api_key: str | None = None,
    base_url: str | None = None,
) -> OpenAICompatibleChat:
    # OpenAICompatibleChat requires base_url; default to OpenAI cloud when omitted.
    return OpenAICompatibleChat(
        model=model,
        base_url=base_url or "https://api.openai.com/v1",
        api_key=api_key or "EMPTY",
    )
