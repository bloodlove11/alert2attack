"""Shared JSON helpers for LLM structured outputs."""

from __future__ import annotations

import json
import re
from typing import Any

from alert2attack.domain.casefile import CaseFile, clip_summary_sentences

_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)
_CASEFILE_FIELDS = frozenset(CaseFile.model_fields)


def extract_json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    m = _JSON_RE.search(text)
    if not m:
        raise ValueError("no JSON object in model output")
    data = json.loads(m.group(0))
    if not isinstance(data, dict):
        raise ValueError("JSON root must be an object")
    return data


def normalize_casefile_dict(payload: dict[str, Any]) -> dict[str, Any]:
    """Tolerate common 7B CaseFile JSON drift without inventing claims.

    - Drop unknown top-level keys (e.g. case_id / case_name).
    - Alias description → summary only when summary is absent.
    - Default missing confidence to low when a verdict is present.
    - Clip summary to 3 real sentences (not raw `.exe` / `T1218.005` / hostname periods).
    Never invents verdict, techniques, timeline, or evidence ids.
    """
    data = dict(payload)
    if "summary" not in data and isinstance(data.get("description"), str):
        data["summary"] = data.pop("description")
    else:
        data.pop("description", None)
    normalized = {key: value for key, value in data.items() if key in _CASEFILE_FIELDS}
    if "verdict" in normalized and "confidence" not in normalized:
        normalized["confidence"] = "low"
    summary = normalized.get("summary")
    if isinstance(summary, str) and summary.strip():
        normalized["summary"] = clip_summary_sentences(summary)
    return normalized


def parse_case_file(raw: str) -> CaseFile:
    """Extract, normalize, and validate CaseFile JSON. Raises on failure."""
    return CaseFile.model_validate(normalize_casefile_dict(extract_json_object(raw)))
