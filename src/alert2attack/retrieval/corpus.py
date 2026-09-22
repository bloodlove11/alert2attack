"""The document set that search runs over.

Two sources, kept apart by ``kind``:

- ATT&CK techniques, from a catalog file (see ``DEFAULT_CATALOG``).
- The vendored Sigma rules, from ``KnowledgeBase``.

The catalog is not committed. ATT&CK is large and versioned, so it lives in the
gitignored ``datasets/raw/`` and is pinned by the revision file that sits next
to it. Without it the corpus falls back to the 30 techniques vendored with the
agent. That is enough to run the search box but is **not a valid benchmark
corpus**. Those 30 were chosen around the answer key: 16 of them are dev gold
ids, so the candidate set has already been narrowed towards the right answers.
A random top-5 hits 27% of the time over these 30 and 1.2% over the full 697,
so any method looks more than twenty times better than it is.
``bench`` refuses a corpus below ``MIN_BENCH_TECHNIQUES`` for that reason.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from alert2attack.knowledge.base import KnowledgeBase

DocKind = Literal["attack_technique", "sigma_rule"]

DEFAULT_CATALOG = Path("datasets/raw/attack_catalog.json")
CATALOG_ENV = "ALERT2ATTACK_ATTACK_CATALOG"

# Below this a retrieval benchmark says nothing. See the module docstring.
MIN_BENCH_TECHNIQUES = 300

# bge-small takes 512 tokens; ~2000 characters is comfortably inside that.
MAX_TEXT_CHARS = 1800

_CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_SPACE_RE = re.compile(r"\s+")


class Doc(BaseModel):
    """One searchable document. ``doc_id`` follows the evidence-id grammar, so a
    hit can be handed straight to ``lookup_attack_technique`` or a citation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    doc_id: str
    kind: DocKind
    title: str
    text: str
    tactics: list[str] = Field(default_factory=list)


def clean_description(text: str) -> str:
    """Strip ATT&CK's inline citation markers and markdown links.

    ``(Citation: Mandiant APT1)`` is noise to a retriever, and a markdown link
    contributes its URL as tokens if left in.
    """
    text = _CITATION_RE.sub("", text)
    text = _MD_LINK_RE.sub(r"\1", text)
    return _SPACE_RE.sub(" ", text).strip()


def technique_doc_id(technique_id: str) -> str:
    return f"attack-{technique_id}"


class Corpus(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    docs: list[Doc]
    source: str
    catalog_revision: str | None = None

    def of_kind(self, kind: DocKind) -> list[Doc]:
        return [d for d in self.docs if d.kind == kind]

    @property
    def n_techniques(self) -> int:
        return len(self.of_kind("attack_technique"))

    def by_id(self) -> dict[str, Doc]:
        return {d.doc_id: d for d in self.docs}

    def fingerprint(self) -> str:
        """Stable hash of what was indexed, so an index is rebuilt when it changes."""
        digest = hashlib.sha256()
        for doc in sorted(self.docs, key=lambda d: d.doc_id):
            digest.update(doc.doc_id.encode())
            digest.update(b"\0")
            digest.update(doc.text.encode())
            digest.update(b"\0")
        return digest.hexdigest()[:16]


def _catalog_docs(entries: Iterable[dict[str, Any]]) -> list[Doc]:
    entries = list(entries)
    names = {e["id"]: e["name"] for e in entries}
    docs: list[Doc] = []
    for entry in entries:
        # Enterprise only: the agent investigates Windows endpoint telemetry, and
        # mobile and ICS techniques would only add distractors. Deprecated ids
        # are dropped, because ATT&CK has retired them.
        if entry.get("domain") != "enterprise" or entry.get("deprecated"):
            continue
        name = entry["name"]
        parent = entry.get("parent_id")
        # ATT&CK names a sub-technique "Parent: Child". The child's description
        # alone is often generic ("Adversaries may abuse ..."); the parent name
        # carries most of the meaning.
        title = f"{names[parent]}: {name}" if parent and parent in names else name
        description = clean_description(entry.get("description", ""))
        docs.append(
            Doc(
                doc_id=technique_doc_id(entry["id"]),
                kind="attack_technique",
                title=title,
                text=f"{title}. {description}"[:MAX_TEXT_CHARS],
            )
        )
    return docs


def _sigma_docs(knowledge: KnowledgeBase) -> list[Doc]:
    docs: list[Doc] = []
    for slug in knowledge.rule_slugs():
        rule = knowledge.rule(slug)
        if rule is None:  # pragma: no cover - rule_slugs came from the same map
            continue
        # Tags are left out on purpose. They name the technique directly
        # ("attack.t1059.001"), which would make a rule a free answer key for any
        # query that resembles its alert.
        docs.append(
            Doc(
                doc_id=f"rule-{rule.slug}",
                kind="sigma_rule",
                title=rule.title,
                text=f"{rule.title}. {rule.description}"[:MAX_TEXT_CHARS],
            )
        )
    return docs


def _vendored_technique_docs(knowledge: KnowledgeBase) -> list[Doc]:
    docs: list[Doc] = []
    for technique_id in knowledge.technique_ids():
        technique = knowledge.technique(technique_id)
        if technique is None:  # pragma: no cover
            continue
        docs.append(
            Doc(
                doc_id=technique_doc_id(technique.technique_id),
                kind="attack_technique",
                title=technique.name,
                text=f"{technique.name}. {technique.description}"[:MAX_TEXT_CHARS],
                tactics=list(technique.tactics),
            )
        )
    return docs


def catalog_path() -> Path:
    return Path(os.environ.get(CATALOG_ENV, DEFAULT_CATALOG))


def _read_revision(path: Path) -> str | None:
    """The catalog's pin, if a REVISION file sits beside it."""
    for name in ("attack_REVISION.json", "REVISION.json"):
        candidate = path.parent / name
        if candidate.is_file():
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return None
            version = data.get("attack_version")
            return f"ATT&CK v{version}" if version else None
    return None


def build_corpus(
    *,
    catalog: Path | None = None,
    knowledge: KnowledgeBase | None = None,
    include_sigma: bool = True,
) -> Corpus:
    """The full catalog when it exists, otherwise the vendored 30.

    Falling back is deliberate: the search box should work on a bare checkout.
    The fallback is recorded in ``Corpus.source`` so nothing downstream can
    mistake it for the real thing.
    """
    knowledge = knowledge or KnowledgeBase.load_default()
    path = catalog if catalog is not None else catalog_path()

    if path.is_file():
        entries = json.loads(path.read_text(encoding="utf-8"))
        techniques = _catalog_docs(entries)
        source = f"catalog:{path.name}"
        revision = _read_revision(path)
    else:
        techniques = _vendored_technique_docs(knowledge)
        source = "vendored"
        revision = None

    docs = techniques + (_sigma_docs(knowledge) if include_sigma else [])
    return Corpus(docs=docs, source=source, catalog_revision=revision)
