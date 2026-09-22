"""Text embedders.

Two implementations behind one protocol:

- ``FastEmbedder``: a real sentence-embedding model, run locally on CPU through
  ONNX. No API key and no per-call cost, which matches the rest of the stack.
  Its first use downloads the model weights, which is why it is constructed
  explicitly rather than by default.
- ``HashEmbedder``: signed feature hashing of tokens. It has **no semantics**: two
  texts are close only if they share words. It exists so the store, the fusion
  and the API can be tested deterministically with no download. Never report a
  benchmark number from it as if it were a dense model.
"""

from __future__ import annotations

import hashlib
import math
import os
from collections.abc import Sequence
from typing import Protocol

from alert2attack.retrieval.lexical import tokenize

DEFAULT_MODEL = "BAAI/bge-small-en-v1.5"

CACHE_ENV = "ALERT2ATTACK_EMBEDDER_CACHE"
DEFAULT_CACHE = "datasets/raw/embedder_cache"


def embedder_cache_dir() -> str:
    """Where model weights land. Under the gitignored ``datasets/raw/`` rather than
    fastembed's default of the system temp directory, which gets cleaned and would
    trigger a fresh download."""
    return os.environ.get(CACHE_ENV, DEFAULT_CACHE)


class Embedder(Protocol):
    name: str
    dim: int

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]: ...

    def embed_query(self, text: str) -> list[float]: ...


class HashEmbedder:
    def __init__(self, dim: int = 256) -> None:
        self.dim = dim
        self.name = f"hash-{dim}"

    def _vector(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for token in tokenize(text):
            digest = hashlib.blake2b(token.encode(), digest_size=8).digest()
            bucket = int.from_bytes(digest[:4], "little") % self.dim
            sign = 1.0 if digest[4] & 1 else -1.0
            vec[bucket] += sign
        norm = math.sqrt(sum(v * v for v in vec))
        return [v / norm for v in vec] if norm else vec

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        return [self._vector(t) for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._vector(text)


class FastEmbedder:
    """``fastembed`` wrapper. Imports lazily so the base install never needs it."""

    def __init__(self, model: str = DEFAULT_MODEL, *, cache_dir: str | None = None) -> None:
        try:
            from fastembed import TextEmbedding
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise RuntimeError(
                "fastembed is not installed; run `uv sync --group retrieval`"
            ) from exc
        self.name = model
        self._model = TextEmbedding(model_name=model, cache_dir=cache_dir or embedder_cache_dir())
        self.dim = int(TextEmbedding.get_embedding_size(model))

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        return [[float(x) for x in vec] for vec in self._model.embed(list(texts))]

    def embed_query(self, text: str) -> list[float]:
        # bge models are trained with an instruction on the query side only;
        # fastembed's query_embed applies it, embed does not.
        vec = next(iter(self._model.query_embed(text)))
        return [float(x) for x in vec]
