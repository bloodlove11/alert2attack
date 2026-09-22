"""Qdrant as the vector store.

``QdrantStore`` runs three ways from one code path:

- in memory (tests, one-off runs),
- embedded on disk (``path=``): qdrant-client's local mode, no container,
- against a server (``http://...``): the compose profile.

Local mode is the default because most readers will never start a database to try
a search box. It is the same client API, so nothing above this file changes when
a real server is pointed at.

**On the choice of Qdrant.** For ~700 documents a dedicated vector database is
overkill: sqlite-vec would give the same answers with no new service and the same
file as everything else. Qdrant is here to work hands-on with a dedicated vector
store and its embedded mode, which is a preference and not a technical need.
docs/DESIGN-console.md D4 says so. If the extra dependency stops being worth it,
sqlite-vec is the correct migration and the corpus is small enough that it costs an
afternoon.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Protocol

from alert2attack.retrieval.corpus import Doc, DocKind

_NAMESPACE = uuid.UUID("5b0a1d1e-7d1f-4e0f-9c55-3c1f3f7f2a10")


class VectorStore(Protocol):
    def ensure_index(
        self,
        name: str,
        docs: Sequence[Doc],
        embed: Callable[[Sequence[str]], list[list[float]]],
    ) -> None: ...

    def search(
        self, vector: Sequence[float], *, k: int, kind: DocKind | None = None
    ) -> list[tuple[str, float]]: ...


def _point_id(doc_id: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, doc_id))


class QdrantStore:
    def __init__(self, location: str | Path | None = None, *, dim: int) -> None:
        try:
            from qdrant_client import QdrantClient
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise RuntimeError(
                "qdrant-client is not installed; run `uv sync --group retrieval`"
            ) from exc

        self._dim = dim
        self._collection: str | None = None
        text = None if location is None else str(location)
        if text is None or text == ":memory:":
            self._client = QdrantClient(location=":memory:")
        elif text.startswith(("http://", "https://")):
            self._client = QdrantClient(url=text)
        else:
            self._client = QdrantClient(path=text)

    def close(self) -> None:
        self._client.close()

    def ensure_index(
        self,
        name: str,
        docs: Sequence[Doc],
        embed: Callable[[Sequence[str]], list[list[float]]],
    ) -> None:
        """Idempotent. The collection name carries a fingerprint of the corpus and
        embedder, so an unchanged index is reused without re-embedding, and a
        changed one lands in a fresh collection instead of a stale one."""
        from qdrant_client import models

        self._collection = name
        if self._client.collection_exists(name):
            return

        vectors = embed([d.text for d in docs])
        self._client.create_collection(
            collection_name=name,
            vectors_config=models.VectorParams(size=self._dim, distance=models.Distance.COSINE),
        )
        self._client.upsert(
            collection_name=name,
            points=[
                models.PointStruct(
                    id=_point_id(doc.doc_id),
                    vector=list(vec),
                    payload={"doc_id": doc.doc_id, "kind": doc.kind, "title": doc.title},
                )
                for doc, vec in zip(docs, vectors, strict=True)
            ],
        )

    def search(
        self, vector: Sequence[float], *, k: int, kind: DocKind | None = None
    ) -> list[tuple[str, float]]:
        from qdrant_client import models

        if self._collection is None:
            raise RuntimeError("ensure_index must run before search")
        query_filter = (
            models.Filter(must=[models.FieldCondition(key="kind", match=models.MatchValue(value=kind))])
            if kind is not None
            else None
        )
        response = self._client.query_points(
            collection_name=self._collection,
            query=list(vector),
            limit=k,
            query_filter=query_filter,
            with_payload=True,
        )
        return [(str(p.payload["doc_id"]), float(p.score)) for p in response.points if p.payload]
