"""Public Investigator entrypoint."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from alert2attack.agent.budget import Budget
from alert2attack.agent.graph import InvestigationGraph, run_graph
from alert2attack.agent.llm import ChatModel, ScriptedChat, ollama_from_env
from alert2attack.agent.progress import ProgressEmitter, ProgressSink
from alert2attack.agent.trace import Trace
from alert2attack.domain.casefile import CaseFile
from alert2attack.domain.scenario import SCENARIOS_ROOT, Scenario, load_scenario
from alert2attack.knowledge.base import KnowledgeBase
from alert2attack.store.case_store import CaseStore
from alert2attack.tools import default_registry
from alert2attack.tools.context import EvidenceLedger, ToolContext
from alert2attack.tools.registry import ToolRegistry
from alert2attack.verify.models import VerificationReport


@dataclass
class InvestigationResult:
    case_file: CaseFile
    trace: Trace
    verification: VerificationReport | None = None
    pre_repair_case_file: CaseFile | None = None


class Investigator:
    def __init__(
        self,
        *,
        llm: ChatModel,
        registry: ToolRegistry | None = None,
        knowledge: KnowledgeBase | None = None,
        budget: Budget | None = None,
        skip_plan: bool = False,
        max_investigate_turns: int = 0,
        max_repairs: int = 2,
        progress: ProgressSink | None = None,
    ) -> None:
        self.llm = llm
        self.registry = registry or default_registry()
        self.knowledge = knowledge or KnowledgeBase.load_default()
        self.budget = budget or Budget()
        self.skip_plan = skip_plan
        self.max_investigate_turns = max_investigate_turns
        self.max_repairs = max_repairs
        # None means NullSink: the CLI and the eval runner observe nothing.
        self.progress = progress

    def run_scenario(self, scenario: Scenario) -> InvestigationResult:
        public = scenario.public()
        store = CaseStore()
        store.load_case(public)
        ledger = EvidenceLedger()
        ctx = ToolContext(
            store=store,
            case_id=public.scenario_id,
            ledger=ledger,
            knowledge=self.knowledge,
        )
        trace = Trace(case_id=public.scenario_id, model=self.llm.model_name)
        emitter = ProgressEmitter(self.progress)
        built = InvestigationGraph(
            llm=self.llm,
            registry=self.registry,
            ctx=ctx,
            budget=self.budget,
            trace=trace,
            skip_plan=self.skip_plan,
            max_investigate_turns=self.max_investigate_turns,
            max_repairs=self.max_repairs,
            progress=emitter,
        ).build()
        turn_cap = self.max_investigate_turns if self.max_investigate_turns > 0 else 256
        state = run_graph(built, recursion_limit=turn_cap + self.max_repairs * 2 + 8)
        trace.tool_calls = list(ledger.calls)
        trace.budget = self.budget.snapshot()
        case_file = state.get("case_file")
        if case_file is None:
            raise RuntimeError("investigation graph did not produce a case_file")
        verification = state.get("verification")
        # Emitted here rather than inside verify_node: that node has several exit
        # paths and the status is only final once the graph has stopped.
        if verification is not None:
            emitter.verification(verification)
        pre_repair = state.get("pre_repair_case_file")
        return InvestigationResult(
            case_file=case_file,
            trace=trace,
            verification=verification,
            pre_repair_case_file=pre_repair,
        )

    def run(self, scenario_id: str, *, root: Path = SCENARIOS_ROOT) -> InvestigationResult:
        return self.run_scenario(load_scenario(root / scenario_id))


def build_chat_model(kind: str, **kwargs: Any) -> ChatModel:
    key = kind.lower().strip()
    if key in {"scripted", "script"}:
        responses = kwargs.get("responses")
        if not responses:
            raise ValueError("ScriptedChat requires responses=[...]")
        return ScriptedChat(responses)
    if key in {"ollama", "local", "local-7b"}:
        return ollama_from_env(model=kwargs.get("model"), base_url=kwargs.get("base_url"))
    if key in {"openai", "teacher"}:
        from alert2attack.agent.teacher import teacher_chat

        return teacher_chat(model=kwargs.get("model"))
    raise ValueError(f"unknown chat model kind '{kind}'")
