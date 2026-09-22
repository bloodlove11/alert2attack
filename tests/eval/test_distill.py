"""Distill JSONL must persist real chat turns for non-scripted teacher/live LLMs."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from alert2attack.agent.llm import ChatMessage, ChatResponse, ScriptedChat
from alert2attack.cli import app
from alert2attack.eval.distill import scripted_prompt_messages
from alert2attack.eval.runner import run_eval

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "scenarios" / "enc_ps_downloader_001"
_CASEFILE = {
    "verdict": "malicious",
    "confidence": "high",
    "summary": "Encoded PowerShell downloaded a remote script.",
    "timeline": [{"ts": "2024-03-12T10:00:00Z", "text": "ps", "evidence": ["ev-0004"]}],
    "techniques": [{"technique_id": "T1059.001", "evidence": ["ev-0004"], "note": ""}],
    "scope": {
        "root_process": {"text": "cmd", "evidence": ["ev-0004"]},
        "involved_pids": [5288],
        "persistence": [],
        "beyond_process": False,
    },
    "next_actions": [
        {"action": "isolate_host", "rationale": {"text": "c2", "evidence": ["ev-0004"]}},
    ],
    "open_questions": [],
}


class FakeLiveChat:
    """ChatModel stand-in that is not ScriptedChat and does not record .calls."""

    def __init__(self, responses: Sequence[ChatResponse], *, model_name: str = "fake-teacher") -> None:
        self._responses = list(responses)
        self._model_name = model_name

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
        del messages, tools, tool_choice
        if not self._responses:
            raise RuntimeError("FakeLiveChat: no responses left")
        return self._responses.pop(0)


def _queued_responses() -> list[ChatResponse]:
    payload = json.dumps(_CASEFILE)
    return [
        ChatResponse(content="plan: inspect encoded powershell"),
        ChatResponse(content="ready to write"),
        ChatResponse(content=payload),
        ChatResponse(content=payload),
        ChatResponse(content=payload),
    ]


def _dev_scenario_root(tmp_path: Path) -> Path:
    root = tmp_path / "scenarios"
    dest = root / "enc_ps_downloader_001"
    dest.mkdir(parents=True)
    manifest = (FIXTURE / "manifest.yaml").read_text(encoding="utf-8")
    dest.joinpath("manifest.yaml").write_text(
        manifest.replace("split: test", "split: dev", 1),
        encoding="utf-8",
    )
    dest.joinpath("events.jsonl").write_text(
        (FIXTURE / "events.jsonl").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return root


def test_non_scripted_teacher_distill_has_chat_messages(tmp_path: Path) -> None:
    llm = FakeLiveChat(_queued_responses())
    assert not isinstance(llm, ScriptedChat)
    assert scripted_prompt_messages(llm) is None

    distill = tmp_path / "teacher-dev.jsonl"
    report = run_eval(
        arm="agent-teacher",
        split="dev",
        root=_dev_scenario_root(tmp_path),
        out_dir=tmp_path / "reports",
        llm=llm,
        export_distill=distill,
    )
    assert report.n == 1
    row = json.loads(distill.read_text(encoding="utf-8").splitlines()[0])
    assert row["split"] == "dev"
    assert row["messages"], "live teacher distill rows must contain the chat thread, not []"
    turns = row["messages"]
    assert isinstance(turns, list) and isinstance(turns[0], list)
    flat = [msg for turn in turns for msg in turn]
    roles = {msg["role"] for msg in flat}
    assert "user" in roles or "system" in roles
    assert "assistant" in roles
    assert any((msg.get("content") or "").strip() for msg in flat)
    assert any("plan: inspect encoded powershell" in (msg.get("content") or "") for msg in flat)
    # Trace ledger should also carry the turns (not only char counts).
    llm_calls = row["trace"]["llm_calls"]
    assert llm_calls
    assert any(call.get("messages") for call in llm_calls)


def test_scripted_chat_distill_still_has_messages(tmp_path: Path) -> None:
    distill = tmp_path / "scripted-dev.jsonl"
    report = run_eval(
        arm="agent-scripted",
        split="dev",
        root=_dev_scenario_root(tmp_path),
        out_dir=tmp_path / "reports",
        llm=ScriptedChat(_queued_responses()),
        export_distill=distill,
    )
    assert report.n == 1
    row = json.loads(distill.read_text(encoding="utf-8").splitlines()[0])
    assert row["messages"]
    flat = [msg for turn in row["messages"] for msg in turn]
    assert any(msg.get("role") == "assistant" for msg in flat)


def test_eval_cli_refuses_export_distill_on_test_split(tmp_path: Path) -> None:
    out = tmp_path / "leaked.jsonl"
    result = CliRunner().invoke(
        app,
        [
            "eval",
            "run",
            "--arm",
            "agent-scripted",
            "--split",
            "test",
            "--export-distill",
            str(out),
            "--limit",
            "1",
        ],
    )
    assert result.exit_code == 2
    assert "export-distill" in result.output.lower() or "never" in result.output.lower()
    assert "test" in result.output.lower()
    assert not out.exists()


def test_distill_redacts_api_keys_from_messages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret-teacher-key-123")
    poisoned = [
        ChatResponse(content="plan using sk-secret-teacher-key-123"),
        ChatResponse(content="ready"),
        ChatResponse(content=json.dumps(_CASEFILE)),
        ChatResponse(content=json.dumps(_CASEFILE)),
        ChatResponse(content=json.dumps(_CASEFILE)),
    ]
    distill = tmp_path / "redact.jsonl"
    run_eval(
        arm="agent-teacher",
        split="dev",
        root=_dev_scenario_root(tmp_path),
        out_dir=tmp_path / "reports",
        llm=FakeLiveChat(poisoned),
        export_distill=distill,
    )
    blob = distill.read_text(encoding="utf-8")
    assert "sk-secret-teacher-key-123" not in blob
    row = json.loads(blob.splitlines()[0])
    assert row["messages"]
