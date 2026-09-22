"""Curated OTRF dataset catalog."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class CatalogEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9_]+$")
    url: HttpUrl
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    techniques: list[str] = Field(default_factory=list)
    preferred_host_substring: str | None = None
    notes: str = ""


def load_catalog(path: Path) -> list[CatalogEntry]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = raw.get("datasets", raw) if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise ValueError("catalog must be a list or {datasets: [...]}")
    return [CatalogEntry.model_validate(item) for item in entries]


DEFAULT_CATALOG = Path(__file__).resolve().parents[3] / "datasets" / "catalog.yaml"
