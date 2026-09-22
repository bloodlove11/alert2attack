"""An optional agent tool over the retrieval stack.

**Off by default.** ``default_registry()`` does not include it, and a test pins the
default tool list, because a new tool changes what the model is shown and the
frozen OTRF numbers were measured without it. Nothing has measured whether this
tool makes an investigation better. There is no model available to run that
experiment, and `docs/RETRIEVAL_EVAL.md` reports retrieval quality only.

**A hit is not evidence.** The tool returns candidate technique ids and gives the
ledger nothing: no evidence ids. To cite a technique the agent still has to call
``lookup_attack_technique``, which is what puts ``attack-T####`` in the ledger.
Otherwise a search result would count as "fetched", and
``technique_candidates_from_ledger`` would turn every suggestion into a write
candidate. Search proposes; lookup is what the verifier accepts.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from alert2attack.retrieval.retriever import Mode, Retriever
from alert2attack.tools import default_registry
from alert2attack.tools.context import ToolContext, ToolResult
from alert2attack.tools.registry import ToolRegistry

TOOL_NAME = "search_attack_techniques"


class SearchArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str = Field(
        min_length=3,
        max_length=500,
        description="What the behavior looks like, in plain words, e.g. 'mshta runs a remote script'",
    )
    k: int = Field(default=5, ge=1, le=10, description="How many candidates to return")


def register_retrieval_tools(registry: ToolRegistry, retriever: Retriever) -> None:
    mode: Mode = "hybrid" if "hybrid" in retriever.modes else "lexical"

    @registry.register(
        TOOL_NAME,
        "Search ATT&CK technique descriptions by meaning to find candidate technique ids for a "
        "behavior you have seen. Returns candidates only, not evidence: call lookup_attack_technique "
        "on an id before citing it.",
        SearchArgs,
    )
    def search_attack_techniques(ctx: ToolContext, args: Any) -> ToolResult:
        hits = retriever.search(args.query, mode=mode, k=args.k, kind="attack_technique")
        return ToolResult(
            data={
                "mode": mode,
                "candidates": [
                    {
                        "technique_id": h.doc_id.removeprefix("attack-"),
                        "title": h.title,
                        "rank": h.rank,
                    }
                    for h in hits
                ],
                "note": "candidates only; call lookup_attack_technique to cite one",
            },
            evidence_ids=[],
        )


def retrieval_registry(retriever: Retriever) -> ToolRegistry:
    """The default tools plus search. Built only when a caller asks for it."""
    registry = default_registry()
    register_retrieval_tools(registry, retriever)
    return registry
