"""Verification report models (Phase 4)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class VerificationError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    code: str
    message: str


class VerificationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    passed: bool
    status: Literal["passed", "repaired", "degraded"] = "passed"
    errors: list[VerificationError] = Field(default_factory=list)
    pre_repair_errors: list[VerificationError] = Field(default_factory=list)
    repairs_used: int = 0
    stripped_claims: int = 0

    @property
    def citation_validity_pre(self) -> float:
        """Fraction of claim-evidence slots that were valid before repair (1.0 if none)."""
        return _validity_ratio(self.pre_repair_errors)

    @property
    def citation_validity_post(self) -> float:
        return _validity_ratio(self.errors)


def _validity_ratio(errors: list[VerificationError]) -> float:
    # Proxy: any citation-class error counts against validity; exact slot counts need
    # the case file. Report helpers in eval (Phase 5) refine this; here 0/1 by presence.
    cite_codes = {
        "UNKNOWN_EVIDENCE",
        "EVIDENCE_NOT_IN_LEDGER",
        "EMPTY_EVIDENCE",
    }
    cite_errs = [e for e in errors if e.code in cite_codes]
    if not cite_errs:
        return 1.0
    # Soft score: fewer citation errors → higher; clamp
    return max(0.0, 1.0 - 0.15 * len(cite_errs))
