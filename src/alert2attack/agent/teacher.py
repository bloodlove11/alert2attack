"""Resolve the cloud teacher ChatModel from environment.

Preference order:
1. ``EXPLABS_API_KEY`` → Experiential Labs OpenAI-compatible API
2. ``OPENAI_API_KEY`` → OpenAI cloud

Optional:
- ``ALERT2ATTACK_TEACHER_MODEL`` — e.g. ``gpt-5.6-luna``, ``deepseek-v4-flash``, ``qwen3.8-27b``
- ``ALERT2ATTACK_TEACHER_BASE_URL`` — override base URL
"""

from __future__ import annotations

import os

from alert2attack.agent.llm import OpenAIChat, OpenAICompatibleChat

EXPLABS_BASE_URL = "https://api.experientiallabs.ai/v1"  # pragma: allowlist secret
EXPLABS_DEFAULT_MODEL = "gpt-5.6-luna"
OPENAI_DEFAULT_MODEL = "gpt-4o-mini"


def teacher_chat(*, model: str | None = None) -> OpenAICompatibleChat:
    """Build the teacher LLM from env (ExpLabs preferred over OpenAI)."""
    explabs_key = os.environ.get("EXPLABS_API_KEY")
    openai_key = os.environ.get("OPENAI_API_KEY")
    base_override = os.environ.get("ALERT2ATTACK_TEACHER_BASE_URL")

    if explabs_key:
        return OpenAIChat(
            model=model or os.environ.get("ALERT2ATTACK_TEACHER_MODEL", EXPLABS_DEFAULT_MODEL),
            api_key=explabs_key,
            base_url=base_override or EXPLABS_BASE_URL,
        )
    if openai_key:
        return OpenAIChat(
            model=model or os.environ.get("ALERT2ATTACK_TEACHER_MODEL", OPENAI_DEFAULT_MODEL),
            api_key=openai_key,
            base_url=base_override,
        )
    raise RuntimeError(
        "Teacher needs EXPLABS_API_KEY (Experiential Labs) or OPENAI_API_KEY. "
        "Set ALERT2ATTACK_TEACHER_MODEL to gpt-5.6-luna | deepseek-v4-flash | qwen3.8-27b "
        "(ExpLabs) or an OpenAI model id."
    )


def teacher_configured() -> bool:
    return bool(os.environ.get("EXPLABS_API_KEY") or os.environ.get("OPENAI_API_KEY"))
