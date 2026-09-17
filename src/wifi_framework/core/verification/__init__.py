"""
Verification Engine subsystem.

Decides whether observations and suspected findings are sufficiently supported and reports the
conclusion as a ``verification-result``. When evidence is insufficient it returns a
``VerificationActionRequest`` for the Decision Engine instead of running a tool itself.

Specification section 19: "The Verification Engine does not directly control arbitrary tools."
This package imports no execution machinery.
"""
from __future__ import annotations

from .engine import (
    CLAIM_EVIDENCE_REQUIREMENTS,
    CONTRADICT_TOLERANCE,
    REFUTE_MARGIN,
    VerificationEngine,
    VerificationOutcome,
    noisy_or,
)

__all__ = [
    "VerificationEngine",
    "VerificationOutcome",
    "noisy_or",
    "CLAIM_EVIDENCE_REQUIREMENTS",
    "REFUTE_MARGIN",
    "CONTRADICT_TOLERANCE",
]
