"""Evidence id grammar.

Three families exist:
- ``ev-NNNN``      a telemetry event returned by a tool in this run
- ``rule-<slug>``  a vendored Sigma rule looked up in this run
- ``attack-T####`` an ATT&CK technique looked up in this run

The verifier (Phase 4) accepts nothing outside this grammar.
"""

import re
from typing import Annotated

from pydantic import StringConstraints

EVIDENCE_ID_PATTERN = r"^(ev-\d{4,}|rule-[a-z0-9_\-]+|attack-T\d{4}(\.\d{3})?)$"
_EVIDENCE_ID_RE = re.compile(EVIDENCE_ID_PATTERN)

EvidenceId = Annotated[str, StringConstraints(pattern=EVIDENCE_ID_PATTERN)]


def is_evidence_id(value: str) -> bool:
    return _EVIDENCE_ID_RE.match(value) is not None


def rule_evidence_id(slug: str) -> str:
    return f"rule-{slug}"


def technique_evidence_id(technique_id: str) -> str:
    return f"attack-{technique_id}"
