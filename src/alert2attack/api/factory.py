"""Chat model factory helpers for the API."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from alert2attack.agent.llm import ChatModel, ScriptedChat, ollama_from_env, scripted_responses_from_json
from alert2attack.agent.replay import ReplayChat

ChatFactory = Callable[[str], ChatModel]


def default_chat_factory(model: str) -> ChatModel:
    key = model.lower().strip()
    if key in {"ollama", "local", "local-7b"}:
        return ollama_from_env()
    if key in {"openai", "teacher"}:
        from alert2attack.agent.teacher import teacher_chat

        return teacher_chat()
    if key == "replay":
        # A canned responder, not an investigator. See alert2attack.agent.replay.
        return ReplayChat()
    if key == "scripted":
        raise ValueError("scripted model requires an injected chat factory for tests")
    raise ValueError(
        f"unknown model {model!r}; expected ollama|local-7b|openai|teacher|replay|scripted"
    )


def scripted_from_responses_json(path: Path) -> ChatModel:
    return ScriptedChat(scripted_responses_from_json(path))
