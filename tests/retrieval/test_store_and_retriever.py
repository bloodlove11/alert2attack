"""The Qdrant store and the retriever that fuses both channels."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("qdrant_client", reason="needs `uv sync --group retrieval`")

from alert2attack.retrieval.corpus import Corpus, Doc  # noqa: E402
from alert2attack.retrieval.embedder import HashEmbedder  # noqa: E402
from alert2attack.retrieval.retriever import ModeUnavailable, Retriever  # noqa: E402
from alert2attack.retrieval.store import QdrantStore  # noqa: E402

TECHNIQUES = {
    "attack-T1003.001": ("OS Credential Dumping: LSASS Memory", "dump credentials from lsass process memory"),
    "attack-T1059.001": ("Command and Scripting Interpreter: PowerShell", "powershell encoded command execution"),
    "attack-T1053.005": ("Scheduled Task", "scheduled task persistence at logon"),
    "attack-T1218.005": ("System Binary Proxy Execution: Mshta", "mshta executes html application scripts"),
}


def _corpus() -> Corpus:
    docs = [
        Doc(doc_id=i, kind="attack_technique", title=title, text=f"{title}. {text}")
        for i, (title, text) in TECHNIQUES.items()
    ]
    docs.append(
        Doc(
            doc_id="rule-win_susp_mshta",
            kind="sigma_rule",
            title="Suspicious Mshta",
            text="Suspicious Mshta. mshta launched",
        )
    )
    return Corpus(docs=docs, source="test")


def _retriever(location: str | Path | None = None) -> Retriever:
    embedder = HashEmbedder()
    return Retriever(_corpus(), embedder=embedder, store=QdrantStore(location, dim=embedder.dim))


# -- the store ----------------------------------------------------------------


def test_the_store_finds_the_nearest_document() -> None:
    embedder = HashEmbedder()
    store = QdrantStore(None, dim=embedder.dim)
    corpus = _corpus()
    store.ensure_index("t1", corpus.docs, embedder.embed_documents)

    hits = store.search(embedder.embed_query("dump credentials lsass"), k=3)
    assert hits[0][0] == "attack-T1003.001"
    store.close()


def test_the_kind_filter_is_applied_inside_the_store() -> None:
    embedder = HashEmbedder()
    store = QdrantStore(None, dim=embedder.dim)
    store.ensure_index("t1", _corpus().docs, embedder.embed_documents)

    only_rules = store.search(embedder.embed_query("mshta"), k=10, kind="sigma_rule")
    assert [d for d, _ in only_rules] == ["rule-win_susp_mshta"]
    store.close()


def test_searching_before_an_index_exists_is_an_error() -> None:
    store = QdrantStore(None, dim=8)
    with pytest.raises(RuntimeError, match="ensure_index"):
        store.search([0.0] * 8, k=1)
    store.close()


def test_an_existing_index_is_reused_without_re_embedding(tmp_path: Path) -> None:
    """Embedding is the slow part. An unchanged corpus must not pay for it twice."""
    embedder = HashEmbedder()
    calls = {"n": 0}

    def counting(texts: list[str]) -> list[list[float]]:
        calls["n"] += 1
        return embedder.embed_documents(texts)

    first = QdrantStore(tmp_path / "q", dim=embedder.dim)
    first.ensure_index("same-name", _corpus().docs, counting)
    first.close()
    assert calls["n"] == 1

    second = QdrantStore(tmp_path / "q", dim=embedder.dim)
    second.ensure_index("same-name", _corpus().docs, counting)
    assert calls["n"] == 1, "the persisted collection should have been reused"
    assert second.search(embedder.embed_query("powershell encoded"), k=1)[0][0] == "attack-T1059.001"
    second.close()


def test_a_changed_corpus_gets_a_fresh_collection(tmp_path: Path) -> None:
    """The retriever names the collection by fingerprint, so an edit re-indexes."""
    embedder = HashEmbedder()
    a = Retriever(_corpus(), embedder=embedder, store=QdrantStore(tmp_path / "q", dim=embedder.dim))
    a.close()

    edited = Corpus(
        docs=[*_corpus().docs, Doc(doc_id="attack-T9999", kind="attack_technique", title="New", text="New. brand new")],
        source="test",
    )
    assert edited.fingerprint() != _corpus().fingerprint()
    b = Retriever(edited, embedder=embedder, store=QdrantStore(tmp_path / "q", dim=embedder.dim))
    assert b.search("brand new", mode="dense", k=1)[0].doc_id == "attack-T9999"
    b.close()


# -- the retriever ------------------------------------------------------------


def test_a_lexical_only_retriever_reports_only_lexical() -> None:
    retriever = Retriever(_corpus())
    assert retriever.modes == ["lexical"]
    assert retriever.embedder_name is None


def test_dense_search_without_an_embedder_is_a_clear_error() -> None:
    retriever = Retriever(_corpus())
    with pytest.raises(ModeUnavailable):
        retriever.search("lsass", mode="dense")
    with pytest.raises(ModeUnavailable):
        retriever.search("lsass", mode="hybrid")


def test_embedder_and_store_come_as_a_pair() -> None:
    with pytest.raises(ValueError, match="both or neither"):
        Retriever(_corpus(), embedder=HashEmbedder())


def test_all_three_modes_are_available_with_an_embedder() -> None:
    retriever = _retriever()
    assert retriever.modes == ["lexical", "dense", "hybrid"]
    assert retriever.embedder_name == "hash-256"
    retriever.close()


@pytest.mark.parametrize("mode", ["lexical", "dense", "hybrid"])
def test_every_mode_finds_the_obvious_answer(mode: str) -> None:
    retriever = _retriever()
    hits = retriever.search("dump credentials from lsass memory", mode=mode, k=3)  # type: ignore[arg-type]
    assert hits[0].doc_id == "attack-T1003.001"
    retriever.close()


def test_hits_carry_rank_score_and_title() -> None:
    retriever = _retriever()
    hits = retriever.search("scheduled task logon", mode="lexical", k=2)
    assert [h.rank for h in hits] == [1, 2][: len(hits)]
    assert hits[0].title == "Scheduled Task"
    assert hits[0].score > 0
    retriever.close()


def test_hybrid_reports_which_channels_ranked_each_hit() -> None:
    """So a UI can show that a hit came from meaning, from shared words, or both."""
    retriever = _retriever()
    top = retriever.search("powershell encoded command", mode="hybrid", k=3)[0]
    assert top.doc_id == "attack-T1059.001"
    assert set(top.channel_ranks) == {"lexical", "dense"}
    assert top.channel_ranks["lexical"] == 1
    retriever.close()


def test_single_channel_modes_report_only_their_channel() -> None:
    retriever = _retriever()
    lexical = retriever.search("powershell", mode="lexical", k=1)[0]
    dense = retriever.search("powershell", mode="dense", k=1)[0]
    assert set(lexical.channel_ranks) == {"lexical"}
    assert set(dense.channel_ranks) == {"dense"}
    retriever.close()


def test_kind_filtering_holds_in_every_mode() -> None:
    retriever = _retriever()
    for mode in ("lexical", "dense", "hybrid"):
        hits = retriever.search("mshta", mode=mode, k=10, kind="attack_technique")  # type: ignore[arg-type]
        assert hits, mode
        assert {h.kind for h in hits} == {"attack_technique"}, mode
    retriever.close()


def test_k_is_respected() -> None:
    retriever = _retriever()
    assert len(retriever.search("execution", mode="hybrid", k=2)) <= 2
    retriever.close()


def test_a_query_with_no_shared_words_finds_nothing_lexically() -> None:
    """The gap the dense channel is meant to fill. Whether it fills it is a claim
    about a real embedding model, and the hash embedder cannot back it either way."""
    retriever = _retriever()
    assert retriever.search("zzzz", mode="lexical", k=3) == []
    retriever.close()
