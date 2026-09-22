"""Retrieval benchmark: does search find the right ATT&CK technique?

    uv run --group retrieval python -m alert2attack.retrieval.bench --embedder fastembed

It measures retrieval only. No language model runs, so there is no verdict
accuracy here and nothing in it says the agent would investigate better. It
answers a narrower question: given text an analyst could search with, how high
does each method rank the technique the answer key names?

Dev split only, and enforced. The 13 test scenarios are the frozen headline
slice. Tuning retrieval against them would repeat the mistake the sibling
CVE-to-ATT&CK repo had to footnote into uselessness (a post-hoc-tuned 0.504).
``load_dev_cases`` never loads a test scenario and ``evaluate`` refuses one that
is handed to it, so the guarantee holds even if a caller builds cases by hand.

The headline is pre-registered. ``PRIMARY_QUERY``, ``HEADLINE_K`` and the headline
metrics below were fixed in this file before the first run. Every other query
variant is reported next to it. Picking the best-looking column afterwards would
be a garden of forking paths on 17 cases.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import re
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from alert2attack.domain.scenario import (
    SCENARIOS_ROOT,
    Scenario,
    iter_scenario_dirs,
    load_scenario,
    peek_split,
)
from alert2attack.knowledge.base import KnowledgeBase
from alert2attack.retrieval.corpus import (
    MIN_BENCH_TECHNIQUES,
    Corpus,
    build_corpus,
    technique_doc_id,
)
from alert2attack.retrieval.retriever import Mode, Retriever

PRIMARY_QUERY = "alert+cmdline"
HEADLINE_K = 5
KS = (1, 3, 5, 10)
DEPTH = 20  # ranking depth used for MRR; a first hit below this counts as a miss
WINDOW_CHARS = 1500
BOOTSTRAP_RESAMPLES = 2000
BOOTSTRAP_SEED = 20260920


class TestSplitRefused(RuntimeError):
    """Raised on any attempt to evaluate retrieval against a test scenario."""

    __test__ = False  # not a pytest class, despite the name


_TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def scrub_technique_ids(text: str) -> str:
    """Remove ATT&CK ids from a query.

    OTRF's Atomic Red Team captures carry them in the telemetry itself: the
    bitsadmin scenario's command line downloads ``.../atomics/T1197/T1197.md``, and
    T1197 is its answer. A query containing the answer is not a search.
    """
    return re.sub(r"\s+", " ", _TECHNIQUE_ID_RE.sub(" ", text)).strip()


class Case(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    split: str
    gold: list[str]
    queries: dict[str, str]
    # Technique ids that were present in the raw telemetry and removed from every
    # query. Reported, not hidden: it is a finding about the dataset.
    scrubbed_ids: list[str] = Field(default_factory=list)


# -- queries ------------------------------------------------------------------


def _trigger_text(public: Scenario) -> str:
    trigger = next((e for e in public.events if e.event_id == public.alert.trigger_event_id), None)
    if trigger is None:
        return ""
    parts = (
        trigger.command_line,
        trigger.image,
        trigger.parent_image,
        trigger.target_image,
        trigger.target_path,
        trigger.details,
    )
    return " ".join(p for p in parts if p)


def _window_text(public: Scenario) -> str:
    seen: list[str] = []
    for event in public.events:
        if event.kind.value != "process_create":
            continue
        for value in (event.command_line, event.image):
            if value and value not in seen:
                seen.append(value)
    return " ".join(seen)[:WINDOW_CHARS]


def _raw_queries(public: Scenario, knowledge: KnowledgeBase) -> dict[str, str]:
    if public.gold is not None:
        raise ValueError("queries must be built from a public scenario; gold is still attached")

    rule = knowledge.rule(public.alert.rule_id)
    alert = public.alert.rule_title + (f". {rule.description}" if rule else "")
    cmdline = _trigger_text(public)
    window = _window_text(public)
    return {
        "alert": alert,
        "cmdline": cmdline,
        "window": window,
        "alert+cmdline": f"{alert} {cmdline}".strip(),
    }


def build_queries(public: Scenario, knowledge: KnowledgeBase) -> dict[str, str]:
    """Queries from what an analyst sees, with any ATT&CK ids removed.

    Built from ``Scenario.public()`` only. Sigma tags are never used: they name
    the technique outright (``attack.t1059.001``), so a query that included them
    would be reading the answer. The rule's title and description are what the
    alert itself shows.
    """
    return {k: scrub_technique_ids(v) for k, v in _raw_queries(public, knowledge).items()}


def load_dev_cases(root: Path = SCENARIOS_ROOT, *, knowledge: KnowledgeBase | None = None) -> list[Case]:
    knowledge = knowledge or KnowledgeBase.load_default()
    cases: list[Case] = []
    for scenario_dir in iter_scenario_dirs(root):
        # Peek first so a test scenario is never even parsed here.
        if peek_split(scenario_dir) != "dev":
            continue
        scenario = load_scenario(scenario_dir)
        gold = list(scenario.gold.techniques) if scenario.gold else []
        raw = _raw_queries(scenario.public(), knowledge)
        found = sorted({m.upper() for q in raw.values() for m in _TECHNIQUE_ID_RE.findall(q)})
        cases.append(
            Case(
                scenario_id=scenario.scenario_id,
                split=scenario.split,
                gold=gold,
                queries={k: scrub_technique_ids(v) for k, v in raw.items()},
                scrubbed_ids=found,
            )
        )
    return cases


# -- metrics ------------------------------------------------------------------


class CaseScore(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    n_gold_reachable: int
    first_gold_rank: int | None
    hit: dict[int, float]
    recall: dict[int, float]
    mrr: float


def score_ranking(
    ranking: Sequence[str], gold_ids: set[str]
) -> tuple[dict[int, float], dict[int, float], float, int | None]:
    hit: dict[int, float] = {}
    recall: dict[int, float] = {}
    for k in KS:
        found = len(gold_ids & set(ranking[:k]))
        hit[k] = 1.0 if found else 0.0
        recall[k] = found / len(gold_ids)
    first = next((i for i, doc in enumerate(ranking[:DEPTH], start=1) if doc in gold_ids), None)
    return hit, recall, (1.0 / first if first else 0.0), first


def random_reference(n_docs: int, gold_counts: Sequence[int]) -> dict[str, float]:
    """What a ranking with no information would score, in closed form.

    This is the yardstick that shows whether a corpus can discriminate at all. On
    the 30 vendored techniques it says a random top-5 hits 27% of the time, against
    1.2% over the full catalog, so that corpus flatters every method.
    """
    def hit_at(k: int, g: int) -> float:
        if k >= n_docs or g == 0:
            return 1.0 if g else 0.0
        return 1.0 - math.comb(n_docs - g, k) / math.comb(n_docs, k)

    def mrr_of(g: int) -> float:
        if g == 0:
            return 0.0
        total = math.comb(n_docs, g)
        return sum((1.0 / r) * math.comb(n_docs - r, g - 1) / total for r in range(1, n_docs - g + 2))

    counts = [g for g in gold_counts if g > 0]
    n = len(counts)
    if n == 0:
        return {}
    out: dict[str, float] = {}
    for k in KS:
        out[f"hit@{k}"] = sum(hit_at(k, g) for g in counts) / n
        out[f"recall@{k}"] = min(1.0, k / n_docs)
    out["mrr"] = sum(mrr_of(g) for g in counts) / n
    return out


def _mean(values: Sequence[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def bootstrap_ci(values: Sequence[float]) -> tuple[float, float]:
    """95% percentile interval over cases. Wide on 17 cases, and that is the point."""
    rng = random.Random(BOOTSTRAP_SEED)
    n = len(values)
    if n == 0:
        return 0.0, 0.0
    means = sorted(_mean([values[rng.randrange(n)] for _ in range(n)]) for _ in range(BOOTSTRAP_RESAMPLES))
    return means[int(0.025 * BOOTSTRAP_RESAMPLES)], means[int(0.975 * BOOTSTRAP_RESAMPLES) - 1]


def paired_diff_ci(a: Sequence[float], b: Sequence[float]) -> tuple[float, float, float]:
    """Mean of ``a - b`` per case with a bootstrap interval. Paired, because both
    methods answered the same cases and the case is the main source of variance."""
    diffs = [x - y for x, y in zip(a, b, strict=True)]
    lo, hi = bootstrap_ci(diffs)
    return _mean(diffs), lo, hi


# -- evaluation ---------------------------------------------------------------


class MethodResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query_variant: str
    mode: str
    n_cases: int
    metrics: dict[str, float]
    ci: dict[str, tuple[float, float]]
    per_case: list[CaseScore]


class BenchResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generated_at: str
    embedder: str | None
    corpus_source: str
    catalog_revision: str | None
    n_techniques: int
    n_cases_total: int
    n_cases_scored: int
    unreachable_gold: dict[str, list[str]] = Field(default_factory=dict)
    scrubbed_ids: dict[str, list[str]] = Field(default_factory=dict)
    gold_ids_in_raw_telemetry: dict[str, list[str]] = Field(default_factory=dict)
    primary_query: str
    headline_k: int
    methods: list[MethodResult]
    random_reference: dict[str, float]
    paired: dict[str, dict[str, tuple[float, float, float]]]
    notes: list[str] = Field(default_factory=list)


def evaluate(
    cases: Sequence[Case],
    retriever: Retriever,
    *,
    modes: Sequence[Mode] | None = None,
    min_techniques: int = MIN_BENCH_TECHNIQUES,
) -> BenchResult:
    for case in cases:
        if case.split != "dev":
            raise TestSplitRefused(
                f"{case.scenario_id} is in the {case.split!r} split; retrieval is tuned and "
                "measured on dev only, and the frozen test slice stays untouched"
            )

    corpus: Corpus = retriever.corpus
    if corpus.n_techniques < min_techniques:
        raise ValueError(
            f"corpus has {corpus.n_techniques} techniques (source: {corpus.source}); a benchmark "
            f"needs at least {min_techniques}. The 30 vendored techniques were chosen around "
            "the answer key, which pre-filters the candidates and makes every method look better "
            "than it is. Put the full catalog at datasets/raw/attack_catalog.json or set "
            "ALERT2ATTACK_ATTACK_CATALOG."
        )

    technique_ids = {d.doc_id for d in corpus.of_kind("attack_technique")}
    modes = list(modes) if modes is not None else list(retriever.modes)

    scored: list[tuple[Case, set[str]]] = []
    unreachable: dict[str, list[str]] = {}
    scrubbed = {c.scenario_id: c.scrubbed_ids for c in cases if c.scrubbed_ids}
    # The subset that matters: the id that was sitting in the telemetry was the answer.
    answer_in_telemetry = {
        c.scenario_id: sorted(set(c.scrubbed_ids) & {g.upper() for g in c.gold})
        for c in cases
        if set(c.scrubbed_ids) & {g.upper() for g in c.gold}
    }
    for case in cases:
        gold_ids = {technique_doc_id(t) for t in case.gold}
        reachable = gold_ids & technique_ids
        missing = sorted(g.removeprefix("attack-") for g in gold_ids - technique_ids)
        if missing:
            unreachable[case.scenario_id] = missing
        # A scenario with no reachable gold (benign lookalikes have none at all)
        # has nothing to retrieve and cannot be scored.
        if reachable:
            scored.append((case, reachable))

    variants = list(scored[0][0].queries) if scored else []
    methods: list[MethodResult] = []
    for variant in variants:
        for mode in modes:
            per_case: list[CaseScore] = []
            for case, gold_ids in scored:
                hits = retriever.search(case.queries[variant], mode=mode, k=DEPTH, kind="attack_technique")
                ranking = [h.doc_id for h in hits]
                hit, recall, mrr, first = score_ranking(ranking, gold_ids)
                per_case.append(
                    CaseScore(
                        scenario_id=case.scenario_id,
                        n_gold_reachable=len(gold_ids),
                        first_gold_rank=first,
                        hit=hit,
                        recall=recall,
                        mrr=mrr,
                    )
                )
            metrics: dict[str, float] = {"mrr": _mean([c.mrr for c in per_case])}
            ci: dict[str, tuple[float, float]] = {"mrr": bootstrap_ci([c.mrr for c in per_case])}
            for k in KS:
                metrics[f"hit@{k}"] = _mean([c.hit[k] for c in per_case])
                metrics[f"recall@{k}"] = _mean([c.recall[k] for c in per_case])
                ci[f"hit@{k}"] = bootstrap_ci([c.hit[k] for c in per_case])
                ci[f"recall@{k}"] = bootstrap_ci([c.recall[k] for c in per_case])
            methods.append(
                MethodResult(
                    query_variant=variant,
                    mode=mode,
                    n_cases=len(per_case),
                    metrics=metrics,
                    ci=ci,
                    per_case=per_case,
                )
            )

    paired = _paired(methods)
    return BenchResult(
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        embedder=retriever.embedder_name,
        corpus_source=corpus.source,
        catalog_revision=corpus.catalog_revision,
        n_techniques=corpus.n_techniques,
        n_cases_total=len(cases),
        n_cases_scored=len(scored),
        unreachable_gold=unreachable,
        scrubbed_ids=scrubbed,
        gold_ids_in_raw_telemetry=answer_in_telemetry,
        primary_query=PRIMARY_QUERY,
        headline_k=HEADLINE_K,
        methods=methods,
        random_reference=random_reference(corpus.n_techniques, [len(g) for _, g in scored]),
        paired=paired,
    )


def _recall_at_headline(c: CaseScore) -> float:
    return c.recall[HEADLINE_K]


def _mrr(c: CaseScore) -> float:
    return c.mrr


_PAIRED_METRICS: tuple[tuple[str, Callable[[CaseScore], float]], ...] = (
    (f"recall@{HEADLINE_K}", _recall_at_headline),
    ("mrr", _mrr),
)


def _paired(methods: Sequence[MethodResult]) -> dict[str, dict[str, tuple[float, float, float]]]:
    """Per query variant: hybrid minus lexical and dense minus lexical, on recall@5 and MRR."""
    out: dict[str, dict[str, tuple[float, float, float]]] = {}
    by_key = {(m.query_variant, m.mode): m for m in methods}
    for variant in {m.query_variant for m in methods}:
        base = by_key.get((variant, "lexical"))
        if base is None:
            continue
        for mode in ("dense", "hybrid"):
            other = by_key.get((variant, mode))
            if other is None:
                continue
            for name, pick in _PAIRED_METRICS:
                key = f"{variant}|{mode}-lexical|{name}"
                out.setdefault(variant, {})[key] = paired_diff_ci(
                    [pick(c) for c in other.per_case], [pick(c) for c in base.per_case]
                )
    return out


# -- output -------------------------------------------------------------------


def render_markdown(result: BenchResult) -> str:
    def cell(m: MethodResult, key: str) -> str:
        lo, hi = m.ci[key]
        return f"{m.metrics[key]:.2f} ({lo:.2f}–{hi:.2f})"

    lines = [
        f"Corpus: {result.n_techniques} enterprise techniques ({result.corpus_source}"
        + (f", {result.catalog_revision}" if result.catalog_revision else "")
        + f"). Embedder: {result.embedder or 'none'}. Dev scenarios scored: "
        f"{result.n_cases_scored} of {result.n_cases_total}.",
        "",
    ]
    ref = result.random_reference
    lines += [
        "| Query | Method | hit@5 | recall@5 | MRR |",
        "|---|---|---|---|---|",
    ]
    for m in result.methods:
        star = " (headline)" if m.query_variant == result.primary_query else ""
        lines.append(
            f"| {m.query_variant}{star} | {m.mode} | {cell(m, 'hit@5')} | {cell(m, 'recall@5')} | {cell(m, 'mrr')} |"
        )
    if ref:
        lines.append(
            f"| random ranking | none | {ref['hit@5']:.2f} | {ref['recall@5']:.2f} | {ref['mrr']:.2f} |"
        )
    return "\n".join(lines)


def _make_retriever(embedder_kind: str, catalog: Path | None, qdrant: str | None) -> Retriever:
    corpus = build_corpus(catalog=catalog)
    if embedder_kind == "none":
        return Retriever(corpus)

    from alert2attack.retrieval.embedder import FastEmbedder, HashEmbedder
    from alert2attack.retrieval.store import QdrantStore

    embedder = FastEmbedder() if embedder_kind == "fastembed" else HashEmbedder()
    return Retriever(corpus, embedder=embedder, store=QdrantStore(qdrant, dim=embedder.dim))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Retrieval benchmark over the dev scenarios.")
    parser.add_argument("--embedder", choices=["none", "hash", "fastembed"], default="none")
    parser.add_argument("--catalog", type=Path, default=None)
    parser.add_argument("--qdrant", default=None, help="':memory:', a directory, or http://host:6333")
    parser.add_argument("--out", type=Path, default=None, help="write the full result as JSON")
    args = parser.parse_args(argv)

    retriever = _make_retriever(args.embedder, args.catalog, args.qdrant)
    try:
        result = evaluate(load_dev_cases(), retriever)
    finally:
        retriever.close()

    if args.embedder == "hash":
        result.notes.append(
            "hash embedder has no semantics; this run checks the plumbing and is not a dense-retrieval result"
        )
    if args.out:
        args.out.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    print(render_markdown(result))
    for note in result.notes:
        print(f"\nNOTE: {note}", file=sys.stderr)
    return 0


def _as_json(value: Any) -> str:  # pragma: no cover - debugging aid
    return json.dumps(value, indent=2, default=str)


if __name__ == "__main__":
    raise SystemExit(main())
