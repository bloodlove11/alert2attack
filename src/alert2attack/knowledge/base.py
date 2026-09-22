import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

DATA_DIR = Path(__file__).resolve().parent / "data"


class SigmaRule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    slug: str
    title: str
    description: str
    level: str
    tags: list[str] = Field(default_factory=list)
    falsepositives: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    detection: dict[str, Any] = Field(default_factory=dict)

    @property
    def attack_technique_ids(self) -> list[str]:
        ids: list[str] = []
        for tag in self.tags:
            if tag.lower().startswith("attack.t"):
                ids.append(tag.split(".", 1)[1].upper())
        return ids


class AttackTechnique(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    technique_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str
    tactics: list[str]
    description: str


class KnowledgeBase:
    def __init__(self, rules: dict[str, SigmaRule], techniques: dict[str, AttackTechnique]) -> None:
        self._rules = rules
        self._techniques = techniques

    @classmethod
    def load_default(cls) -> "KnowledgeBase":
        return cls.load(DATA_DIR)

    @classmethod
    def load(cls, data_dir: Path) -> "KnowledgeBase":
        rules: dict[str, SigmaRule] = {}
        for path in sorted((data_dir / "sigma").glob("*.yaml")):
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            raw.setdefault("slug", path.stem)
            rule = SigmaRule.model_validate(raw)
            rules[rule.slug] = rule
        raw_techniques = json.loads((data_dir / "attack_techniques.json").read_text(encoding="utf-8"))
        techniques = {t["technique_id"]: AttackTechnique.model_validate(t) for t in raw_techniques}
        return cls(rules, techniques)

    def rule(self, slug: str) -> SigmaRule | None:
        return self._rules.get(slug)

    def technique(self, technique_id: str) -> AttackTechnique | None:
        return self._techniques.get(technique_id.upper())

    def rule_slugs(self) -> list[str]:
        return sorted(self._rules)

    def technique_ids(self) -> list[str]:
        return sorted(self._techniques)
