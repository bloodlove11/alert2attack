"""One search facade over the lexical channel, the dense channel and their fusion."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from alert2attack.retrieval.corpus import Corpus, DocKind
from alert2attack.retrieval.embedder import Embedder
from alert2attack.retrieval.fusion import reciprocal_rank_fusion
from alert2attack.retrieval.lexical import BM25
from alert2attack.retrieval.store import VectorStore

Mode = Literal["lexical", "dense", "hybrid"]

# How deep each channel looks before fusion. Fusing only each channel's top 10
# would throw away a document that both channels rank 11th, which is exactly the
# kind of agreement RRF is meant to reward.
CANDIDATE_POOL = 50


class Hit(BaseModel):
    model_config = ConfigDict(extra="forbid")

    doc_id: str
    title: str
    kind: DocKind
    score: float
    rank: int
    # Which channel ranked this document, and where. Lets a UI show that a hit
    # came from meaning rather than from shared words, or from both.
    channel_ranks: dict[str, int] = Field(default_factory=dict)


class ModeUnavailable(RuntimeError):
    """Dense or hybrid was asked for on a retriever built without an embedder."""


class Retriever:
    def __init__(
        self,
        corpus: Corpus,
        *,
        embedder: Embedder | None = None,
        store: VectorStore | None = None,
    ) -> None:
        if (embedder is None) != (store is None):
            raise ValueError("embedder and store come as a pair: both or neither")
        self.corpus = corpus
        self._docs = corpus.by_id()
        self._bm25 = BM25({d.doc_id: d.text for d in corpus.docs})
        self._embedder = embedder
        self._store = store

        if embedder is not None and store is not None:
            store.ensure_index(
                f"alert2attack_{corpus.fingerprint()}_{embedder.name.replace('/', '_')}",
                corpus.docs,
                embedder.embed_documents,
            )

    @property
    def modes(self) -> list[Mode]:
        return ["lexical", "dense", "hybrid"] if self._embedder is not None else ["lexical"]

    @property
    def embedder_name(self) -> str | None:
        return self._embedder.name if self._embedder is not None else None

    def _allowed(self, kind: DocKind | None) -> set[str] | None:
        if kind is None:
            return None
        return {d.doc_id for d in self.corpus.docs if d.kind == kind}

    def _lexical(self, query: str, k: int, kind: DocKind | None) -> list[tuple[str, float]]:
        return self._bm25.search(query, k=k, allowed=self._allowed(kind))

    def _dense(self, query: str, k: int, kind: DocKind | None) -> list[tuple[str, float]]:
        if self._embedder is None or self._store is None:
            raise ModeUnavailable("dense search needs an embedder; install `--group retrieval`")
        return self._store.search(self._embedder.embed_query(query), k=k, kind=kind)

    def search(
        self,
        query: str,
        *,
        mode: Mode = "hybrid",
        k: int = 10,
        kind: DocKind | None = None,
    ) -> list[Hit]:
        if mode == "lexical":
            ranked = self._lexical(query, k, kind)
            channels = {"lexical": [d for d, _ in ranked]}
        elif mode == "dense":
            ranked = self._dense(query, k, kind)
            channels = {"dense": [d for d, _ in ranked]}
        else:
            lexical = self._lexical(query, CANDIDATE_POOL, kind)
            dense = self._dense(query, CANDIDATE_POOL, kind)
            channels = {"lexical": [d for d, _ in lexical], "dense": [d for d, _ in dense]}
            ranked = reciprocal_rank_fusion(list(channels.values()))[:k]

        hits: list[Hit] = []
        for rank, (doc_id, score) in enumerate(ranked[:k], start=1):
            doc = self._docs[doc_id]
            hits.append(
                Hit(
                    doc_id=doc_id,
                    title=doc.title,
                    kind=doc.kind,
                    score=score,
                    rank=rank,
                    channel_ranks={
                        name: order.index(doc_id) + 1
                        for name, order in channels.items()
                        if doc_id in order
                    },
                )
            )
        return hits

    def close(self) -> None:
        close = getattr(self._store, "close", None)
        if callable(close):
            close()
