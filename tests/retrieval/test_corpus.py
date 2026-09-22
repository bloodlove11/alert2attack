"""The document set: catalog parsing, the fallback, and the answer-key guards."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from alert2attack.retrieval.corpus import (
    Corpus,
    Doc,
    build_corpus,
    clean_description,
    technique_doc_id,
)


def _entry(id_: str, name: str, **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": id_,
        "name": name,
        "description": f"Adversaries may use {name}.",
        "domain": "enterprise",
        "is_subtechnique": "." in id_,
        "parent_id": id_.split(".")[0] if "." in id_ else None,
        "deprecated": False,
    }
    base.update(overrides)
    return base


def _write_catalog(tmp_path: Path, entries: list[dict[str, Any]], revision: str | None = None) -> Path:
    path = tmp_path / "attack_catalog.json"
    path.write_text(json.dumps(entries), encoding="utf-8")
    if revision:
        (tmp_path / "attack_REVISION.json").write_text(
            json.dumps({"attack_version": revision}), encoding="utf-8"
        )
    return path


# -- cleaning -----------------------------------------------------------------


def test_citation_markers_are_stripped() -> None:
    text = "Adversaries dump LSASS memory. (Citation: Mandiant APT1) They then pivot. (Citation: X)"
    assert "Citation" not in clean_description(text)
    assert "pivot" in clean_description(text)


def test_markdown_links_keep_their_text_and_lose_the_url() -> None:
    cleaned = clean_description("See [Windows Command Shell](https://attack.mitre.org/techniques/T1059/003) now")
    assert cleaned == "See Windows Command Shell now"


def test_whitespace_is_collapsed() -> None:
    assert clean_description("a\n\n  b\t c") == "a b c"


# -- the catalog --------------------------------------------------------------


def test_only_current_enterprise_techniques_are_indexed(tmp_path: Path) -> None:
    path = _write_catalog(
        tmp_path,
        [
            _entry("T1059", "Command and Scripting Interpreter"),
            _entry("T1003", "OS Credential Dumping", deprecated=True),
            _entry("T0800", "Activate Firmware Update Mode", domain="ics"),
            _entry("T1400", "Mobile Thing", domain="mobile"),
        ],
    )
    corpus = build_corpus(catalog=path, include_sigma=False)
    assert [d.doc_id for d in corpus.docs] == ["attack-T1059"]


def test_a_subtechnique_is_titled_with_its_parent(tmp_path: Path) -> None:
    """ATT&CK's own convention, and the parent carries most of the meaning."""
    path = _write_catalog(
        tmp_path,
        [
            _entry("T1059", "Command and Scripting Interpreter"),
            _entry("T1059.001", "PowerShell"),
        ],
    )
    docs = {d.doc_id: d for d in build_corpus(catalog=path, include_sigma=False).docs}
    assert docs["attack-T1059.001"].title == "Command and Scripting Interpreter: PowerShell"
    assert docs["attack-T1059.001"].text.startswith("Command and Scripting Interpreter: PowerShell.")
    assert docs["attack-T1059"].title == "Command and Scripting Interpreter"


def test_doc_ids_follow_the_evidence_grammar(tmp_path: Path) -> None:
    """A hit must be usable as a citation or a lookup with no translation."""
    path = _write_catalog(tmp_path, [_entry("T1059.001", "PowerShell", parent_id=None)])
    (doc,) = build_corpus(catalog=path, include_sigma=False).docs
    assert doc.doc_id == technique_doc_id("T1059.001") == "attack-T1059.001"


def test_the_catalog_revision_is_recorded(tmp_path: Path) -> None:
    path = _write_catalog(tmp_path, [_entry("T1059", "X")], revision="19.2")
    corpus = build_corpus(catalog=path, include_sigma=False)
    assert corpus.catalog_revision == "ATT&CK v19.2"
    assert corpus.source == "catalog:attack_catalog.json"


def test_a_missing_revision_file_is_fine(tmp_path: Path) -> None:
    path = _write_catalog(tmp_path, [_entry("T1059", "X")])
    assert build_corpus(catalog=path, include_sigma=False).catalog_revision is None


# -- the fallback -------------------------------------------------------------


def test_without_a_catalog_the_corpus_falls_back_and_says_so(tmp_path: Path) -> None:
    corpus = build_corpus(catalog=tmp_path / "does-not-exist.json")
    assert corpus.source == "vendored"
    assert corpus.n_techniques == 30
    assert corpus.catalog_revision is None


def test_the_fallback_is_flagged_so_it_cannot_pass_as_the_real_thing() -> None:
    """The 30 vendored techniques were chosen around the answer key."""
    assert build_corpus(catalog=Path("nowhere.json")).source != "catalog:attack_catalog.json"


# -- the answer-key guard -----------------------------------------------------


def test_sigma_docs_never_carry_technique_tags(tmp_path: Path) -> None:
    """Tags name the technique outright ('attack.t1059.001'). Indexing them would
    turn a rule into a free answer key for any query resembling its alert."""
    corpus = build_corpus(catalog=tmp_path / "none.json")
    rules = corpus.of_kind("sigma_rule")
    assert len(rules) == 7
    for doc in rules:
        assert "attack.t" not in doc.text.lower()
        assert doc.doc_id.startswith("rule-")


def test_kinds_are_separable(tmp_path: Path) -> None:
    corpus = build_corpus(catalog=tmp_path / "none.json")
    assert {d.kind for d in corpus.docs} == {"attack_technique", "sigma_rule"}
    assert corpus.n_techniques == len(corpus.of_kind("attack_technique"))


# -- fingerprint --------------------------------------------------------------


def _corpus(*texts: str) -> Corpus:
    return Corpus(
        docs=[Doc(doc_id=f"attack-T{i:04d}", kind="attack_technique", title="t", text=t) for i, t in enumerate(texts)],
        source="test",
    )


def test_fingerprint_is_stable_and_order_independent() -> None:
    a = _corpus("one", "two")
    b = Corpus(docs=list(reversed(a.docs)), source="test")
    assert a.fingerprint() == b.fingerprint()


def test_fingerprint_changes_when_a_text_changes() -> None:
    assert _corpus("one", "two").fingerprint() != _corpus("one", "TWO").fingerprint()
