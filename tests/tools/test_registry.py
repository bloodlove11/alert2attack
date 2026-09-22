from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, Field

from alert2attack.domain.scenario import Scenario
from alert2attack.knowledge.base import KnowledgeBase
from alert2attack.store.case_store import CaseStore
from alert2attack.tools.context import EvidenceLedger, ToolContext, ToolResult
from alert2attack.tools.registry import ToolRegistry


class EchoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    n: int = Field(ge=0, description="how many ids to return")


@pytest.fixture
def ctx(downloader_scenario: Scenario) -> ToolContext:
    store = CaseStore()
    store.load_case(downloader_scenario.public())
    return ToolContext(
        store=store,
        case_id=downloader_scenario.scenario_id,
        ledger=EvidenceLedger(),
        knowledge=KnowledgeBase.load_default(),
    )


@pytest.fixture
def registry() -> ToolRegistry:
    reg = ToolRegistry()

    @reg.register("echo", "Return n fake evidence ids.", EchoArgs)
    def echo(ctx: ToolContext, args: Any) -> ToolResult:
        ids = [f"ev-{i:04d}" for i in range(1, args.n + 1)]
        return ToolResult(data={"n": args.n}, evidence_ids=ids)

    @reg.register("boom", "Always raises.", EchoArgs)
    def boom(ctx: ToolContext, args: Any) -> ToolResult:
        raise RuntimeError("kaboom")

    return reg


def test_openai_schema_shape(registry: ToolRegistry) -> None:
    schemas = registry.openai_schemas()
    echo = next(s for s in schemas if s["function"]["name"] == "echo")
    assert echo["type"] == "function"
    assert echo["function"]["description"] == "Return n fake evidence ids."
    params = echo["function"]["parameters"]
    assert params["properties"]["n"]["description"] == "how many ids to return"
    assert params["additionalProperties"] is False
    assert registry.names() == ["boom", "echo"]


def test_call_records_evidence_in_ledger(registry: ToolRegistry, ctx: ToolContext) -> None:
    result = registry.call(ctx, "echo", {"n": 2})
    assert result.ok and result.evidence_ids == ["ev-0001", "ev-0002"]
    assert ctx.ledger.ids() == frozenset({"ev-0001", "ev-0002"})
    assert ctx.ledger.has("ev-0001") and not ctx.ledger.has("ev-0003")
    assert len(ctx.ledger.calls) == 1
    rec = ctx.ledger.calls[0]
    assert rec.seq == 1 and rec.tool == "echo" and rec.args == {"n": 2} and rec.ok
    assert rec.duration_ms >= 0
    assert ctx.ledger.first_seen("ev-0002") == 1


def test_unknown_tool_is_an_error_result_not_an_exception(registry: ToolRegistry, ctx: ToolContext) -> None:
    result = registry.call(ctx, "nope", {})
    assert not result.ok and result.error is not None
    assert "unknown tool 'nope'" in result.error and "echo" in result.error
    assert ctx.ledger.calls[-1].ok is False


def test_invalid_args_is_an_error_result(registry: ToolRegistry, ctx: ToolContext) -> None:
    result = registry.call(ctx, "echo", {"n": -1})
    assert not result.ok and result.error is not None and "n" in result.error
    result = registry.call(ctx, "echo", {"n": 1, "extra": True})
    assert not result.ok and result.error is not None and "extra" in result.error
    assert ctx.ledger.ids() == frozenset()


def test_tool_exception_is_captured(registry: ToolRegistry, ctx: ToolContext) -> None:
    result = registry.call(ctx, "boom", {"n": 0})
    assert not result.ok and result.error is not None and "kaboom" in result.error


def test_duplicate_registration_rejected(registry: ToolRegistry) -> None:
    with pytest.raises(ValueError, match="already registered"):

        @registry.register("echo", "dup", EchoArgs)
        def echo2(ctx: ToolContext, args: Any) -> ToolResult:
            return ToolResult()
