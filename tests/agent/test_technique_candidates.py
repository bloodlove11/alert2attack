"""EXP-002 lever 2: ATT&CK write candidates come only from this run's ledger."""

from alert2attack.agent.technique_candidates import technique_candidates_from_ledger
from alert2attack.knowledge.base import KnowledgeBase


def test_extracts_known_attack_ids_sorted_and_deduplicated() -> None:
    knowledge = KnowledgeBase.load_default()

    assert technique_candidates_from_ledger(
        [
            "attack-T1218.005",
            "ev-0004",
            "attack-T1053.005",
            "attack-T1218.005",
        ],
        knowledge,
    ) == ["T1053.005", "T1218.005"]


def test_excludes_rules_events_malformed_and_unknown_techniques() -> None:
    knowledge = KnowledgeBase.load_default()

    assert (
        technique_candidates_from_ledger(
            [
                "rule-win_susp_mshta",
                "ev-0004",
                "attack-t1218.005",
                "attack-T9999",
                "T1218.005",
                "attack-T1218.005-extra",
            ],
            knowledge,
        )
        == []
    )
