"""Deterministic citation verifier and degrade path (Phase 4)."""

from alert2attack.verify.degrade import degrade_casefile
from alert2attack.verify.models import VerificationError, VerificationReport
from alert2attack.verify.verify import verify

__all__ = [
    "VerificationError",
    "VerificationReport",
    "degrade_casefile",
    "verify",
]
