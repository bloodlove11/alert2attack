"""Tools over the vendored knowledge base and the deterministic decoder."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from alert2attack.domain.evidence import rule_evidence_id, technique_evidence_id
from alert2attack.knowledge.powershell import decode_powershell as _decode
from alert2attack.tools.context import ToolContext, ToolResult
from alert2attack.tools.registry import ToolRegistry


class RuleArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str = Field(min_length=1, description="Sigma rule slug exactly as shown in the alert's rule_id")


class TechniqueArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    technique_id: str = Field(
        pattern=r"^[Tt]\d{4}(\.\d{3})?$", description="ATT&CK technique id, e.g. T1059.001"
    )


class DecodeArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command_line: str = Field(min_length=1, description="Full command line to inspect")


def register_knowledge_tools(registry: ToolRegistry) -> None:
    @registry.register(
        "lookup_sigma_rule",
        "Explain the detection rule that fired: what it looks for, its ATT&CK tags and its "
        "documented false positives.",
        RuleArgs,
    )
    def lookup_sigma_rule(ctx: ToolContext, args: Any) -> ToolResult:
        rule = ctx.knowledge.rule(args.rule_id)
        if rule is None:
            return ToolResult.fail(
                f"unknown rule '{args.rule_id}'; known: {', '.join(ctx.knowledge.rule_slugs())}"
            )
        data = rule.model_dump()
        data["attack_technique_ids"] = rule.attack_technique_ids
        return ToolResult(data=data, evidence_ids=[rule_evidence_id(rule.slug)])

    @registry.register(
        "lookup_attack_technique",
        "Return the name, tactic(s) and a short description of an ATT&CK technique id.",
        TechniqueArgs,
    )
    def lookup_attack_technique(ctx: ToolContext, args: Any) -> ToolResult:
        technique = ctx.knowledge.technique(args.technique_id)
        if technique is None:
            return ToolResult.fail(f"unknown ATT&CK technique '{args.technique_id}'")
        return ToolResult(
            data=technique.model_dump(),
            evidence_ids=[technique_evidence_id(technique.technique_id)],
        )

    @registry.register(
        "decode_powershell",
        "Decode a PowerShell -EncodedCommand payload from a command line. Deterministic; the "
        "evidence remains the process event that carried the command line.",
        DecodeArgs,
    )
    def decode_powershell(ctx: ToolContext, args: Any) -> ToolResult:
        result = _decode(args.command_line)
        return ToolResult(data=result.model_dump())
