from alert2attack.knowledge.base import KnowledgeBase


def test_default_knowledge_base_loads_rule_and_techniques() -> None:
    kb = KnowledgeBase.load_default()
    rule = kb.rule("win_powershell_encoded_command")
    assert rule is not None
    assert rule.title == "Suspicious Encoded PowerShell Command Line"
    assert "T1059.001" in rule.attack_technique_ids
    assert rule.falsepositives  # a good rule documents its false positives

    t = kb.technique("T1059.001")
    assert t is not None and t.name == "PowerShell" and "execution" in t.tactics

    assert kb.technique("T9999") is None
    assert kb.rule("nope") is None
    assert "win_powershell_encoded_command" in kb.rule_slugs()
    assert len(kb.rule_slugs()) >= 6
    assert {"T1059.001", "T1547.001", "T1105", "T1003.001", "T1197", "T1003.003"} <= set(kb.technique_ids())
