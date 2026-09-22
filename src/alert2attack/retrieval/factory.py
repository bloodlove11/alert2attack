"""Build a ``Retriever`` from the environment.

    ALERT2ATTACK_EMBEDDER   none (default) | fastembed | hash
    ALERT2ATTACK_QDRANT     :memory: (default) | a directory | http://host:6333
    ALERT2ATTACK_ATTACK_CATALOG   path to the full ATT&CK catalog (see corpus.py)

The default is **lexical only**. A dense channel means downloading model weights
on first use, and nothing should do that silently as a side effect of starting an
API. Opting in is one variable.
"""

from __future__ import annotations

import functools
import os

from alert2attack.retrieval.corpus import build_corpus
from alert2attack.retrieval.retriever import Retriever

EMBEDDER_ENV = "ALERT2ATTACK_EMBEDDER"
QDRANT_ENV = "ALERT2ATTACK_QDRANT"


def default_retriever() -> Retriever:
    corpus = build_corpus()
    kind = os.environ.get(EMBEDDER_ENV, "none").strip().lower()
    if kind in {"", "none"}:
        return Retriever(corpus)

    from alert2attack.retrieval.embedder import FastEmbedder, HashEmbedder
    from alert2attack.retrieval.store import QdrantStore

    if kind == "fastembed":
        embedder: FastEmbedder | HashEmbedder = FastEmbedder()
    elif kind == "hash":
        embedder = HashEmbedder()
    else:
        raise ValueError(f"{EMBEDDER_ENV}={kind!r}; expected none, fastembed or hash")
    location = os.environ.get(QDRANT_ENV) or None
    return Retriever(corpus, embedder=embedder, store=QdrantStore(location, dim=embedder.dim))


@functools.lru_cache(maxsize=1)
def shared_retriever() -> Retriever:
    """One retriever per process. Building a dense one embeds the whole corpus, so
    the API and the agent tool share it instead of paying that per request."""
    return default_retriever()
