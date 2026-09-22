"""Reciprocal rank fusion.

RRF combines rankings using only ranks, never scores. That is the point: BM25
scores and cosine similarities live on unrelated scales, and any weighted sum of
them needs a tuning knob that this project has no held-out data to set honestly.
RRF has one constant, and 60 is the value from the original paper.
"""

from __future__ import annotations

from collections.abc import Sequence

RRF_K = 60


def reciprocal_rank_fusion(
    rankings: Sequence[Sequence[str]],
    *,
    k: int = RRF_K,
) -> list[tuple[str, float]]:
    """Fuse ranked id lists. Earlier in a list scores higher; ids in more lists win."""
    scores: dict[str, float] = {}
    for ranking in rankings:
        for rank, doc_id in enumerate(ranking, start=1):
            scores[doc_id] = scores.get(doc_id, 0.0) + 1.0 / (k + rank)
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))
