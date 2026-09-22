"""Search over ATT&CK techniques and Sigma rules: lexical, dense, and their fusion.

The agent does not use this by default. Nothing here is imported by the graph, and
the default tool registry is unchanged, so the frozen OTRF numbers cannot move.
See docs/RETRIEVAL_EVAL.md for what was measured and how much it can support.
"""

from alert2attack.retrieval.corpus import Corpus, Doc, build_corpus
from alert2attack.retrieval.embedder import Embedder, FastEmbedder, HashEmbedder
from alert2attack.retrieval.retriever import Hit, ModeUnavailable, Retriever

__all__ = [
    "Corpus",
    "Doc",
    "Embedder",
    "FastEmbedder",
    "HashEmbedder",
    "Hit",
    "ModeUnavailable",
    "Retriever",
    "build_corpus",
]
