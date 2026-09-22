"""Eval runner: execute an arm over a scenario split and write reports."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from alert2attack.agent.budget import budget_from_env, max_investigate_turns_from_env
from alert2attack.agent.investigator import Investigator
from alert2attack.agent.llm import ChatMessage, ChatModel, ChatResponse, ScriptedChat, ollama_from_env
from alert2attack.domain.scenario import SCENARIOS_ROOT, Scenario, iter_scenario_dirs, load_scenario, peek_split
from alert2attack.eval.b0 import run_b0
from alert2attack.eval.distill import append_distill_jsonl, distill_record, scripted_prompt_messages
from alert2attack.eval.metrics import AggregateReport, CaseScore, aggregate, score_case

ArmName = Literal["b0", "agent-scripted", "agent-local-7b", "agent-teacher", "agent-noverify"]

B0_BACKENDS = ("auto", "teacher", "ollama")
LIVE_ARMS: tuple[ArmName, ...] = ("b0", "agent-local-7b", "agent-teacher")


def dataset_hash(root: Path) -> str:
    h = hashlib.sha256()
    for manifest in sorted(root.glob("*/manifest.yaml")):
        h.update(manifest.read_bytes())
    return h.hexdigest()[:16]


def _scenarios(root: Path, split: str, limit: int | None) -> list[Scenario]:
    """Load gold scenarios for a split; skip dirs Windows/AV cannot read."""
    import warnings

    out: list[Scenario] = []
    for scenario_dir in iter_scenario_dirs(root):
        if peek_split(scenario_dir) != split:
            continue
        try:
            scenario = load_scenario(scenario_dir)
        except OSError as exc:
            warnings.warn(
                f"skipping unreadable scenario {scenario_dir.name}: {exc}",
                stacklevel=2,
            )
            continue
        if scenario.gold is None:
            continue
        out.append(scenario)
    out.sort(key=lambda s: s.scenario_id)
    if limit is not None:
        out = out[:limit]
    return out


def _b0_llm() -> ChatModel:
    """Live B0 backend: ExpLabs teacher when keyed (apples-to-apples vs agent-teacher), else Ollama.

    ``ALERT2ATTACK_B0_MODEL`` overrides the choice explicitly, so a present-but-unusable
    teacher key (dead gateway route, or a key scoped to another project) does not strand
    the $0 Ollama baseline the live-eval campaign specifies.
    """
    backend = os.environ.get("ALERT2ATTACK_B0_MODEL", "auto").strip().lower() or "auto"
    if backend not in B0_BACKENDS:
        raise RuntimeError(f"ALERT2ATTACK_B0_MODEL must be one of {'|'.join(B0_BACKENDS)}, got {backend!r}")
    if backend == "auto":
        backend = "teacher" if os.environ.get("EXPLABS_API_KEY") else "ollama"
    if backend == "teacher":
        from alert2attack.agent.teacher import teacher_chat

        return teacher_chat()
    return _ollama_llm()


def _ollama_llm() -> ChatModel:
    """Product 7B via Ollama's OpenAI-compatible /v1.

    Defaults to localhost. ``ALERT2ATTACK_OLLAMA_BASE_URL`` points at a remote Ollama
    (Lightning Studio GPU, a laptop worker) without changing the arm name or the model tag.
    """
    return ollama_from_env()


def build_arm_llm(arm: ArmName, *, scripted_responses: list[ChatResponse] | None = None) -> ChatModel:
    if arm in {"b0", "agent-scripted", "agent-noverify"} and scripted_responses is not None:
        return ScriptedChat(scripted_responses)
    if arm == "agent-local-7b":
        return _ollama_llm()
    if arm == "agent-teacher":
        from alert2attack.agent.teacher import teacher_chat

        return teacher_chat()
    if arm == "b0":
        return _b0_llm()
    raise RuntimeError(f"arm {arm} requires scripted_responses in CI or a live model")


def preflight_live_model(llm: ChatModel, *, arm: str) -> None:
    """Probe the route once so an unusable endpoint fails before the split, not mid-split.

    A present API key does not mean a reachable model: gateway aliases go down and keys get
    scoped elsewhere. Without this, the first scenario dies in an SDK traceback that names
    neither the model nor the endpoint.
    """
    try:
        llm.complete([ChatMessage(role="user", content="ok")])
    except Exception as exc:  # noqa: BLE001 — any transport/HTTP failure means the arm cannot run
        endpoint = getattr(llm, "base_url", "<unknown>")
        hint = (
            "check the gateway alias, ALERT2ATTACK_TEACHER_MODEL, and ALERT2ATTACK_TEACHER_BASE_URL; "
            "b0 can run on local Ollama instead with ALERT2ATTACK_B0_MODEL=ollama"
            if arm in {"b0", "agent-teacher"}
            else "check that Ollama is serving, ALERT2ATTACK_OLLAMA_MODEL is pulled, "
            "and ALERT2ATTACK_OLLAMA_BASE_URL reaches the host"
        )
        raise RuntimeError(
            f"arm {arm}: preflight failed for model {llm.model_name!r} at {endpoint} — "
            f"{type(exc).__name__}: {exc}. No scenarios were run; {hint}."
        ) from exc


def run_eval(
    *,
    arm: ArmName,
    split: Literal["dev", "test"] = "dev",
    root: Path = SCENARIOS_ROOT,
    out_dir: Path = Path("reports"),
    limit: int | None = None,
    llm: ChatModel | None = None,
    scripted_factory: Any | None = None,
    export_distill: Path | None = None,
) -> AggregateReport:
    scenarios = _scenarios(root, split, limit)
    if not scenarios:
        raise ValueError(f"no gold scenarios for split={split}")

    if llm is None and scripted_factory is None and arm in LIVE_ARMS:
        preflight_live_model(build_arm_llm(arm), arm=arm)

    scores: list[CaseScore] = []
    for scenario in scenarios:
        assert scenario.gold is not None
        if scripted_factory is not None:
            model = scripted_factory(scenario)
        elif llm is not None:
            model = llm
        else:
            model = build_arm_llm(arm)

        if arm == "b0":
            result = run_b0(scenario, model)
            ledger_ids: set[str] = {e.event_id for e in scenario.events}
        else:
            max_repairs = 0 if arm == "agent-noverify" else 2
            inv = Investigator(
                llm=model,
                budget=budget_from_env(),
                max_repairs=max_repairs,
                max_investigate_turns=max_investigate_turns_from_env(),
            )
            result = inv.run_scenario(scenario)
            ledger_ids = {eid for c in result.trace.tool_calls for eid in c.evidence_ids}

        scores.append(
            score_case(
                scenario_id=scenario.scenario_id,
                gold=scenario.gold,
                result=result,
                ledger_ids=ledger_ids,
            )
        )
        if export_distill is not None:
            append_distill_jsonl(
                export_distill,
                distill_record(scenario, result, prompt_messages=scripted_prompt_messages(model)),
            )

    report = aggregate(arm, split, scores)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y-%m-%d")
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "dataset_hash": dataset_hash(root),
        "report": report.to_dict(),
    }
    path = out_dir / f"{stamp}-{arm}-{split}.json"
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    (out_dir / f"{stamp}-{arm}-{split}.md").write_text(report.markdown_table() + "\n", encoding="utf-8")
    return report
