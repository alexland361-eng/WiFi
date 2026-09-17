"""
Evidence Engine subsystem.

Converts real execution output into structured, traceable evidence (``evidence-set``) and
requests verification for observations that would otherwise be over-trusted.

Specification section 19: "The Evidence Engine does not decide what the next action should be."
Nothing in this package imports the planner, the executor or the registry.
"""
from __future__ import annotations

from .engine import (
    SIGNIFICANT_TYPES,
    VERIFICATION_POLICY,
    WEAK_ENCRYPTION,
    EvidenceEngine,
    EvidenceProcessingResult,
    new_verification_id,
)

__all__ = [
    "EvidenceEngine",
    "EvidenceProcessingResult",
    "new_verification_id",
    "SIGNIFICANT_TYPES",
    "VERIFICATION_POLICY",
    "WEAK_ENCRYPTION",
]
