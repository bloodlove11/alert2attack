"""Teacher provider resolution (ExpLabs / OpenAI)."""

from __future__ import annotations

import pytest

from alert2attack.agent.teacher import teacher_chat, teacher_configured


def test_teacher_prefers_explabs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EXPLABS_API_KEY", "explabs-test-key")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-should-not-win")
    monkeypatch.delenv("ALERT2ATTACK_TEACHER_MODEL", raising=False)
    monkeypatch.delenv("ALERT2ATTACK_TEACHER_BASE_URL", raising=False)
    chat = teacher_chat()
    assert chat.model_name == "gpt-5.6-luna"
    assert "experientiallabs.ai" in str(chat._client.base_url)


def test_teacher_deepseek_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EXPLABS_API_KEY", "explabs-test-key")
    monkeypatch.setenv("ALERT2ATTACK_TEACHER_MODEL", "deepseek-v4-flash")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    chat = teacher_chat()
    assert chat.model_name == "deepseek-v4-flash"


def test_teacher_falls_back_to_openai(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("EXPLABS_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "openai-test-key")
    monkeypatch.delenv("ALERT2ATTACK_TEACHER_MODEL", raising=False)
    chat = teacher_chat()
    assert chat.model_name == "gpt-4o-mini"
    assert "openai.com" in str(chat._client.base_url)


def test_teacher_requires_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("EXPLABS_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert teacher_configured() is False
    with pytest.raises(RuntimeError, match="EXPLABS_API_KEY"):
        teacher_chat()
