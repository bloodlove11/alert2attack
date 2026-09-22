from alert2attack.tools.context import EvidenceLedger, ToolCallRecord, ToolContext, ToolResult
from alert2attack.tools.knowledge_tools import register_knowledge_tools
from alert2attack.tools.registry import ToolRegistry, ToolSpec
from alert2attack.tools.telemetry import register_telemetry_tools


def default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    register_telemetry_tools(registry)
    register_knowledge_tools(registry)
    return registry


__all__ = [
    "EvidenceLedger",
    "ToolCallRecord",
    "ToolContext",
    "ToolRegistry",
    "ToolResult",
    "ToolSpec",
    "default_registry",
]
