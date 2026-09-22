"""Tool registry: name → (args schema, function). The only entry point the agent gets."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from time import perf_counter
from typing import Any

from pydantic import BaseModel, ValidationError

from alert2attack.tools.context import ToolCallRecord, ToolContext, ToolResult

ToolFn = Callable[[ToolContext, Any], ToolResult]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    args_model: type[BaseModel]
    fn: ToolFn


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, name: str, description: str, args_model: type[BaseModel]) -> Callable[[ToolFn], ToolFn]:
        def decorator(fn: ToolFn) -> ToolFn:
            if name in self._tools:
                raise ValueError(f"tool '{name}' already registered")
            self._tools[name] = ToolSpec(name, description, args_model, fn)
            return fn

        return decorator

    def names(self) -> list[str]:
        return sorted(self._tools)

    def spec(self, name: str) -> ToolSpec:
        return self._tools[name]

    def openai_schemas(self) -> list[dict[str, Any]]:
        schemas: list[dict[str, Any]] = []
        for name in self.names():
            spec = self._tools[name]
            params = spec.args_model.model_json_schema()
            params.pop("title", None)
            params.setdefault("additionalProperties", False)
            schemas.append(
                {
                    "type": "function",
                    "function": {"name": name, "description": spec.description, "parameters": params},
                }
            )
        return schemas

    def call(self, ctx: ToolContext, name: str, raw_args: Mapping[str, Any]) -> ToolResult:
        started = perf_counter()
        spec = self._tools.get(name)
        if spec is None:
            result = ToolResult.fail(f"unknown tool '{name}'; available tools: {', '.join(self.names())}")
        else:
            try:
                args = spec.args_model.model_validate(dict(raw_args))
            except ValidationError as exc:
                result = ToolResult.fail(f"invalid arguments for '{name}': {exc.errors(include_url=False)}")
            else:
                try:
                    result = spec.fn(ctx, args)
                except Exception as exc:  # noqa: BLE001 - errors are data, never exceptions, for the agent
                    result = ToolResult.fail(f"tool '{name}' failed: {exc!r}")
        ctx.ledger.record(
            ToolCallRecord(
                seq=len(ctx.ledger.calls) + 1,
                tool=name,
                args=dict(raw_args),
                ok=result.ok,
                evidence_ids=list(result.evidence_ids),
                error=result.error,
                duration_ms=(perf_counter() - started) * 1000.0,
            )
        )
        return result
