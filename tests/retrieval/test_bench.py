"""The retrieval benchmark: its guards matter more than its numbers."""

from __future__ import annotations

import itertools
import math
import re
from pathlib import Path

import pytest

from alert2attack.domain import scenario as scenario_module
from alert2attack.domain.scenario import SCENARIOS_ROOT, load_scenario, peek_split
from alert2attack.knowledge.base import KnowledgeBase
from alert2attack.retrieval import bench
from alert2attack.retrieval.bench import (
    Case,
    TestSplitRefused,
    bootstrap_ci,
    build_queries,
    evaluate,
    load_dev_cases,
    paired_diff_ci,
    random_reference,
    render_markdown,
    score_ranking,
    scrub_technique_ids,
)
from alert2attack.retrieval.corpus import Corpus, Doc, build_corpus
from alert2attack.retrieval.retriever import Retriever

TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def _synthetic_corpus(n: int = 40) -> Corpus:
    """Each technique gets one distinctive word, so lexical search can find it."""
    docs = [
        Doc(
            doc_id=f"attack-T{1000 + i}",
            kind="attack_technique",
            title=f"Technique {i}",
            text=f"Technique {i}. distinctive{i} behaviour number {i}",
        )
        for i in range(n)
    ]
    return Corpus(docs=docs, source="synthetic")


def _case(scenario_id: str, gold: list[str], query: str, split: str = "dev") -> Case:
    return Case(scenario_id=scenario_id, split=split, gold=gold, queries={"q": query})


# -- the test-split guard -----------------------------------------------------


def test_the_test_split_is_refused_by_evaluate() -> None:
    retriever = Retriever(_synthetic_corpus())
    with pytest.raises(TestSplitRefused, match="frozen"):
        evaluate([_case("sneaky", ["T1000"], "distinctive0", split="test")], retriever, min_techniques=1)


def test_one_test_case_among_dev_cases_still_refuses() -> None:
    retriever = Retriever(_synthetic_corpus())
    cases = [_case("ok", ["T1000"], "distinctive0"), _case("bad", ["T1001"], "distinctive1", split="test")]
    with pytest.raises(TestSplitRefused):
        evaluate(cases, retriever, min_techniques=1)


def test_load_dev_cases_returns_only_dev() -> None:
    cases = load_dev_cases()
    assert len(cases) == 20
    assert {c.split for c in cases} == {"dev"}


def test_load_dev_cases_never_parses_a_test_scenario(monkeypatch: pytest.MonkeyPatch) -> None:
    """Not just filtered afterwards: a test scenario is never opened at all."""
    opened: list[str] = []
    real_load = scenario_module.load_scenario

    def spy(path: Path):  # type: ignore[no-untyped-def]
        opened.append(path.name)
        return real_load(path)

    monkeypatch.setattr(bench, "load_scenario", spy)
    load_dev_cases()

    test_ids = {d.name for d in SCENARIOS_ROOT.iterdir() if peek_split(d) == "test"}
    assert len(test_ids) == 13
    assert not (set(opened) & test_ids)


# -- the corpus-size guard ----------------------------------------------------


def test_the_vendored_corpus_is_refused_as_a_benchmark(tmp_path: Path) -> None:
    """Its 30 techniques were chosen around the answer key."""
    retriever = Retriever(build_corpus(catalog=tmp_path / "none.json"))
    with pytest.raises(ValueError, match="chosen around the answer key"):
        evaluate([_case("x", ["T1003.001"], "lsass")], retriever)


def test_the_size_floor_can_be_lowered_explicitly() -> None:
    retriever = Retriever(_synthetic_corpus(10))
    result = evaluate([_case("x", ["T1000"], "distinctive0")], retriever, min_techniques=5)
    assert result.n_cases_scored == 1


# -- queries never read the answer --------------------------------------------


def test_no_dev_query_contains_a_technique_id() -> None:
    """A query that names the technique is not a search, it is the answer."""
    for case in load_dev_cases():
        for variant, query in case.queries.items():
            assert not TECHNIQUE_ID_RE.search(query), f"{case.scenario_id}/{variant} leaks a technique id"


def test_no_dev_query_contains_a_sigma_tag() -> None:
    for case in load_dev_cases():
        for variant, query in case.queries.items():
            assert "attack." not in query.lower(), f"{case.scenario_id}/{variant} contains a Sigma tag"


def test_queries_refuse_a_scenario_that_still_carries_gold() -> None:
    scenario = load_scenario(SCENARIOS_ROOT / "otrf_empire_launcher_vbs")
    assert scenario.gold is not None
    with pytest.raises(ValueError, match="gold is still attached"):
        build_queries(scenario, KnowledgeBase.load_default())


def test_every_dev_case_has_a_non_empty_primary_query() -> None:
    for case in load_dev_cases():
        assert case.queries[bench.PRIMARY_QUERY].strip(), case.scenario_id


def test_gold_lives_on_the_case_but_never_in_a_query() -> None:
    for case in load_dev_cases():
        for gold_id in case.gold:
            for query in case.queries.values():
                assert gold_id not in query


# -- technique ids in the telemetry -------------------------------------------


def test_scrub_removes_ids_from_a_url_path() -> None:
    raw = "bitsadmin /transfer https://raw.githubusercontent.com/x/atomics/T1197/T1197.md C:\\a.ps1"
    cleaned = scrub_technique_ids(raw)
    assert "T1197" not in cleaned
    assert "bitsadmin" in cleaned and "a.ps1" in cleaned


@pytest.mark.parametrize("text", ["run T1059.001 now", "run t1059.001 now", "T1218.005", "see T1105."])
def test_scrub_handles_subtechniques_and_case(text: str) -> None:
    assert not TECHNIQUE_ID_RE.search(scrub_technique_ids(text))


def test_scrub_leaves_words_that_merely_start_with_t() -> None:
    assert scrub_technique_ids("Task T12 and Tools") == "Task T12 and Tools"


def test_scrub_collapses_the_gap_it_leaves() -> None:
    assert scrub_technique_ids("a T1059 b") == "a b"


def test_five_dev_scenarios_carry_the_answer_in_their_telemetry() -> None:
    """A finding about the dataset, pinned so it cannot quietly change.

    OTRF's Atomic Red Team captures put technique ids in URLs and paths. In five
    of the twenty dev scenarios the id in the raw telemetry is a gold technique,
    which means anything reading those command lines can read the answer. The
    queries scrub it; the count is reported.
    """
    cases = load_dev_cases()
    leaky = {c.scenario_id: c for c in cases if c.scrubbed_ids}
    assert len(leaky) == 5
    for case in leaky.values():
        assert set(case.scrubbed_ids) & {g.upper() for g in case.gold}, case.scenario_id


def test_the_result_reports_where_the_answer_was_in_the_telemetry() -> None:
    retriever = Retriever(_synthetic_corpus())
    case = Case(
        scenario_id="c",
        split="dev",
        gold=["T1001"],
        queries={"q": "distinctive1"},
        scrubbed_ids=["T1001", "T1999"],
    )
    result = evaluate([case], retriever, min_techniques=1)
    assert result.scrubbed_ids == {"c": ["T1001", "T1999"]}
    assert result.gold_ids_in_raw_telemetry == {"c": ["T1001"]}


def test_random_reference_of_nothing_is_empty_not_a_crash() -> None:
    assert random_reference(100, []) == {}
    assert random_reference(100, [0, 0]) == {}


def test_markdown_omits_the_random_row_when_there_is_nothing_to_compare() -> None:
    retriever = Retriever(_synthetic_corpus())
    text = render_markdown(evaluate([_case("c", ["T1562.002"], "x")], retriever, min_techniques=1))
    assert "random ranking" not in text


# -- scoring ------------------------------------------------------------------


def test_score_ranking_rank_one() -> None:
    hit, recall, mrr, first = score_ranking(["g", "x", "y"], {"g"})
    assert (hit[1], recall[1], mrr, first) == (1.0, 1.0, 1.0, 1)


def test_score_ranking_partial_recall() -> None:
    hit, recall, mrr, first = score_ranking(["x", "g1", "y", "z", "g2"], {"g1", "g2"})
    assert hit[1] == 0.0 and hit[3] == 1.0
    assert recall[3] == 0.5 and recall[5] == 1.0
    assert first == 2 and mrr == pytest.approx(0.5)


def test_score_ranking_miss() -> None:
    hit, recall, mrr, first = score_ranking(["x", "y"], {"g"})
    assert (hit[5], recall[5], mrr, first) == (0.0, 0.0, 0.0, None)


def test_a_first_hit_deeper_than_the_depth_counts_as_a_miss() -> None:
    ranking = [f"x{i}" for i in range(bench.DEPTH)] + ["g"]
    assert score_ranking(ranking, {"g"})[3] is None


# -- the random baseline ------------------------------------------------------


def _brute_hit(n: int, g: int, k: int) -> float:
    subsets = list(itertools.combinations(range(n), k))
    return sum(1 for s in subsets if any(i < g for i in s)) / len(subsets)


def _brute_mrr(n: int, g: int) -> float:
    total = 0.0
    perms = list(itertools.permutations(range(n)))
    for perm in perms:
        first = next(pos for pos, item in enumerate(perm, start=1) if item < g)
        total += 1.0 / first
    return total / len(perms)


@pytest.mark.parametrize(("n", "g", "k"), [(6, 2, 3), (7, 1, 2), (5, 3, 1), (6, 2, 5)])
def test_random_hit_rate_matches_brute_force(n: int, g: int, k: int) -> None:
    ref = random_reference(n, [g])
    if k in bench.KS:
        assert ref[f"hit@{k}"] == pytest.approx(_brute_hit(n, g, k))
    # k is not always in KS; check the closed form directly as well.
    assert 1.0 - math.comb(n - g, k) / math.comb(n, k) == pytest.approx(_brute_hit(n, g, k))


@pytest.mark.parametrize(("n", "g"), [(5, 2), (6, 1), (5, 3)])
def test_random_mrr_matches_brute_force(n: int, g: int) -> None:
    assert random_reference(n, [g])["mrr"] == pytest.approx(_brute_mrr(n, g))


def test_random_recall_is_k_over_n() -> None:
    assert random_reference(100, [2])["recall@5"] == pytest.approx(0.05)


def test_the_vendored_30_flatters_every_method_by_about_twenty_times() -> None:
    """The finding that reshaped week 3, pinned as a test.

    An earlier draft of this claim said a random top-5 over the vendored 30 hits
    about 98% of the time. That was wrong: it used the union of all dev gold ids
    instead of each scenario's own one or two. Measured on the real answer key, a
    random top-5 hits 27% over the vendored 30 and 1.2% over the 697 current
    enterprise techniques. The 30 are not useless, but they were chosen around the
    answer key, so the candidate set is pre-filtered and every method looks about
    twenty times better than it should.
    """
    counts = [len(c.gold) for c in load_dev_cases() if c.gold]
    assert len(counts) == 17
    assert sorted(set(counts)) == [1, 2], "each scenario has one or two gold techniques"

    small = random_reference(30, counts)["hit@5"]
    full = random_reference(697, counts)["hit@5"]
    assert small == pytest.approx(0.268, abs=0.005)
    assert full == pytest.approx(0.012, abs=0.002)
    assert small / full > 15


# -- statistics ---------------------------------------------------------------


def test_bootstrap_is_deterministic() -> None:
    values = [0.0, 1.0, 1.0, 0.0, 1.0]
    assert bootstrap_ci(values) == bootstrap_ci(values)


def test_bootstrap_interval_brackets_the_mean() -> None:
    values = [0.0, 1.0, 1.0, 0.0, 1.0, 1.0, 0.0, 1.0]
    lo, hi = bootstrap_ci(values)
    assert lo <= sum(values) / len(values) <= hi


def test_a_constant_sample_has_a_degenerate_interval() -> None:
    assert bootstrap_ci([1.0] * 6) == (1.0, 1.0)


def test_the_interval_is_wide_on_a_small_sample() -> None:
    """Seventeen cases cannot separate close methods, and the interval says so."""
    lo, hi = bootstrap_ci([1.0] * 9 + [0.0] * 8)
    assert hi - lo > 0.3


def test_bootstrap_of_nothing_is_zero() -> None:
    assert bootstrap_ci([]) == (0.0, 0.0)


def test_paired_difference_is_signed_the_right_way() -> None:
    mean, lo, hi = paired_diff_ci([1.0, 1.0, 1.0], [0.0, 0.0, 0.0])
    assert mean == 1.0 and lo == hi == 1.0


def test_paired_difference_cancels_shared_case_difficulty() -> None:
    a = [0.9, 0.1, 0.9, 0.1]
    b = [0.8, 0.0, 0.8, 0.0]
    _, lo, hi = paired_diff_ci(a, b)
    assert lo == pytest.approx(0.1) and hi == pytest.approx(0.1)


# -- evaluating ---------------------------------------------------------------


def test_lexical_search_finds_the_distinctive_word() -> None:
    retriever = Retriever(_synthetic_corpus())
    cases = [_case(f"c{i}", [f"T{1000 + i}"], f"distinctive{i}") for i in range(5)]
    result = evaluate(cases, retriever, min_techniques=1)

    (method,) = result.methods
    assert method.mode == "lexical"
    assert method.metrics["hit@1"] == 1.0
    assert method.metrics["mrr"] == 1.0
    assert result.n_cases_scored == 5


def test_a_scenario_with_no_gold_is_unscorable_not_wrong() -> None:
    retriever = Retriever(_synthetic_corpus())
    cases = [_case("benign", [], "distinctive0"), _case("real", ["T1001"], "distinctive1")]
    result = evaluate(cases, retriever, min_techniques=1)
    assert (result.n_cases_total, result.n_cases_scored) == (2, 1)


def test_gold_outside_the_corpus_is_reported_and_not_counted_against_search() -> None:
    """ATT&CK v19.2 has no T1562.002, so no retriever could ever return it."""
    retriever = Retriever(_synthetic_corpus())
    case = _case("c", ["T1001", "T1562.002"], "distinctive1")
    result = evaluate([case], retriever, min_techniques=1)

    assert result.unreachable_gold == {"c": ["T1562.002"]}
    assert result.methods[0].per_case[0].n_gold_reachable == 1
    assert result.methods[0].metrics["recall@1"] == 1.0


def test_a_case_whose_only_gold_is_unreachable_is_dropped_from_scoring() -> None:
    retriever = Retriever(_synthetic_corpus())
    result = evaluate([_case("c", ["T1562.002"], "x")], retriever, min_techniques=1)
    assert result.n_cases_scored == 0
    assert result.methods == []


def test_the_random_reference_travels_with_the_result() -> None:
    retriever = Retriever(_synthetic_corpus())
    result = evaluate([_case("c", ["T1001"], "distinctive1")], retriever, min_techniques=1)
    assert 0 < result.random_reference["hit@5"] < 1


def test_the_primary_query_is_declared_in_the_result() -> None:
    retriever = Retriever(_synthetic_corpus())
    result = evaluate([_case("c", ["T1001"], "distinctive1")], retriever, min_techniques=1)
    assert result.primary_query == bench.PRIMARY_QUERY == "alert+cmdline"
    assert result.headline_k == 5


def test_markdown_includes_the_random_row_and_flags_the_headline() -> None:
    retriever = Retriever(_synthetic_corpus())
    case = Case(
        scenario_id="c",
        split="dev",
        gold=["T1001"],
        queries={bench.PRIMARY_QUERY: "distinctive1", "other": "distinctive1"},
    )
    text = render_markdown(evaluate([case], retriever, min_techniques=1))
    assert "random ranking" in text
    assert f"{bench.PRIMARY_QUERY} (headline)" in text
    assert "| other |" in text


# -- against the real dev set (needs the gitignored catalog) -------------------

CATALOG = Path("datasets/raw/attack_catalog.json")


@pytest.mark.skipif(not CATALOG.is_file(), reason="needs datasets/raw/attack_catalog.json")
def test_lexical_search_beats_random_on_the_real_dev_set() -> None:
    corpus = build_corpus(catalog=CATALOG)
    assert corpus.n_techniques >= bench.MIN_BENCH_TECHNIQUES
    result = evaluate(load_dev_cases(), Retriever(corpus))

    primary = next(m for m in result.methods if m.query_variant == bench.PRIMARY_QUERY)
    assert primary.metrics["recall@5"] > result.random_reference["recall@5"] * 3
    assert result.unreachable_gold, "T1562.002 is absent from ATT&CK v19.2 and should be reported"
