"""A canned responder so the pipeline can run with no model available.

``ReplayChat`` is **not an investigator**. It does no reasoning. It reads the
evidence ids the graph has already put in front of it and returns a well-formed
case file citing them, pacing its turns so a viewer can watch the graph move.

It exists for two reasons the design names directly (§8):

1. A real run on a local 7B takes 60–180 s, which is too slow to film and
   impossible on a machine without Ollama. The console's whole point is the
   live trace, and without this there is nothing to show.
2. A recorded demo should be reproducible. This one is deterministic.

Everything around it is real: the graph runs, tools execute against the store,
the ledger fills, the verifier checks citations, and the deterministic levers
fire. Only the model is fake.

It is deliberately unreachable from evaluation. The eval runner selects models
through ``build_arm_llm``, which knows nothing about this class, and a test
asserts that no eval arm resolves to it. Any number produced with this model
would be meaningless.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Sequence
from time import sleep
from typing import Any

from alert2attack.agent.llm import ChatMessage, ChatResponse, ToolCallRequest

MODEL_NAME = "replay"
DEFAULT_DELAY_MS = 400

_EVIDENCE_RE = re.compile(r"\b(?:ev-\d{4,}|rule-[a-z0-9_\-]+|attack-T\d{4}(?:\.\d{3})?)\b")
_PID_RE = re.compile(r'"pid"\s*:\s*(\d+)')
# The write prompt states the ledger explicitly. Anchoring to that line matters:
# scraping ids from the whole prompt also picks up ids inside truncated tool
# output and the system rubric's examples, which are not citable.
_LEDGER_LINE_RE = re.compile(r"Ledger digest \(ONLY these evidence ids exist\): (\[[^\]]*\])")


def ledger_ids_from_prompt(prompt: str) -> list[str]:
    """Evidence ids the graph says exist, from the write prompt's ledger line."""
    match = _LEDGER_LINE_RE.search(prompt)
    if match is None:
        return sorted(set(_EVIDENCE_RE.findall(prompt)))
    return sorted(set(_EVIDENCE_RE.findall(match.group(1))))


def replay_delay_seconds() -> float:
    """Pacing between turns. Zero in tests; a few hundred ms for a demo."""
    raw = os.environ.get("ALERT2ATTACK_REPLAY_DELAY_MS")
    try:
        return max(0.0, int(raw) / 1000.0) if raw is not None else DEFAULT_DELAY_MS / 1000.0
    except ValueError:
        return DEFAULT_DELAY_MS / 1000.0


def _prompt_text(messages: Sequence[ChatMessage]) -> str:
    return "\n".join(m.content or "" for m in messages)


def _case_file(evidence_ids: list[str]) -> dict[str, Any]:
    cited = evidence_ids[0]
    # Cite every id the ledger showed us, not just the first. The graph
    # hydrates scope.involved_pids from the store, and the verifier then
    # requires each of those pids' process_create events to be cited — citing
    # one id leaves the rest unsupported and the case file ships degraded.
    timeline = [
        {
            "ts": "1970-01-01T00:00:00Z",
            "text": f"Replayed claim over ledger evidence {eid}.",
            "evidence": [eid],
        }
        for eid in evidence_ids
    ]
    return {
        # "malicious" on purpose: it is the verdict the deterministic ceilings
        # act on, so a viewer can watch lever 6 downgrade a benign LSASS alert
        # instead of seeing three levers decline in silence.
        "verdict": "malicious",
        "confidence": "medium",
        "summary": "Replay responder: a canned case file over real ledger evidence.",
        "timeline": timeline,
        "techniques": [],
        "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
        "next_actions": [
            {
                "action": "escalate",
                "rationale": {"text": "Replay responder does not decide.", "evidence": [cited]},
            }
        ],
        "open_questions": ["This case file came from the replay responder, not a model."],
    }


class ReplayChat:
    """Deterministic turns: plan, one tool call, then a case file."""

    def __init__(self, *, delay_s: float | None = None) -> None:
        self.model_name = MODEL_NAME
        self._delay = replay_delay_seconds() if delay_s is None else delay_s
        self._turn = 0

    def complete(
        self,
        messages: Sequence[ChatMessage],
        *,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
    ) -> ChatResponse:
        self._turn += 1
        if self._delay:
            sleep(self._delay)

        prompt = _prompt_text(messages)

        if self._turn == 1:
            return ChatResponse(
                content=(
                    "1. Read the alert and its rule\n"
                    "2. Expand the process tree around the trigger\n"
                    "3. Write the case file from ledger evidence"
                )
            )

        # One real tool call, so the ledger and the trace show tool activity.
        if self._turn == 2:
            pid = _PID_RE.search(prompt)
            if pid is not None:
                return ChatResponse(
                    tool_calls=(
                        ToolCallRequest(
                            id="replay_1",
                            name="get_process_tree",
                            arguments={"pid": int(pid.group(1))},
                        ),
                    )
                )
            return ChatResponse(content="No pid in the alert preview; ready to write.")

        # A second tool call, so the ledger holds more than the trigger event.
        # A one-event ledger makes for a truthful but useless demo.
        if self._turn == 3:
            return ChatResponse(
                tool_calls=(
                    ToolCallRequest(
                        id="replay_2",
                        name="search_events",
                        arguments={"limit": 12},
                    ),
                )
            )

        if self._turn == 4:
            return ChatResponse(content="Ledger is sufficient; ready to write.")

        # Write and any repair turns. Cite only ids the graph has actually shown
        # us, so the verifier passes for the same reason a real run would.
        evidence_ids = [e for e in ledger_ids_from_prompt(prompt) if e.startswith("ev-")]
        if not evidence_ids:
            return ChatResponse(
                content=json.dumps(
                    {
                        "verdict": "not_enough_evidence",
                        "confidence": "low",
                        "summary": "Replay responder saw no evidence ids in the prompt.",
                        "timeline": [],
                        "techniques": [],
                        "scope": {"involved_pids": [], "persistence": [], "beyond_process": False},
                        "next_actions": [],
                        "open_questions": ["No ledger evidence was available."],
                    }
                )
            )
        return ChatResponse(content=json.dumps(_case_file(evidence_ids)))
