"""Investigation agent package."""

from alert2attack.agent.budget import Budget
from alert2attack.agent.investigator import InvestigationResult, Investigator, build_chat_model
from alert2attack.agent.llm import (
    ChatMessage,
    ChatModel,
    ChatResponse,
    OllamaChat,
    OpenAIChat,
    ScriptedChat,
    ToolCallRequest,
)
from alert2attack.agent.trace import Trace

__all__ = [
    "Budget",
    "ChatMessage",
    "ChatModel",
    "ChatResponse",
    "InvestigationResult",
    "Investigator",
    "OllamaChat",
    "OpenAIChat",
    "ScriptedChat",
    "ToolCallRequest",
    "Trace",
    "build_chat_model",
]
