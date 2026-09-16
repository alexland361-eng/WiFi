"""
Finding model - distinguishes between observations, hypotheses, supported findings,
verified findings, and refuted/unresolved hypotheses.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class FindingStatus(str, Enum):
    """Lifecycle of a finding."""
    HYPOTHESIS = "hypothesis"  # Initial guess from limited evidence
    SUPPORTED = "supported"    # Multiple evidences support it
    VERIFIED = "verified"      # Independent verification succeeded
    REFUTED = "refuted"        # Evidence contradicts it
    UNRESOLVED = "unresolved"  # Insufficient evidence to conclude
    CONFIRMED = "confirmed"    # Alias for verified with high confidence


class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(str, Enum):
    WIRELESS = "wireless"
    WPS = "wps"
    AUTHENTICATION = "authentication"
    ENCRYPTION = "encryption"
    NETWORK = "network"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    CONFIGURATION = "configuration"
    CLIENT = "client"


@dataclass
class Finding:
    """
    A security finding that has been reasoned from evidence.

    Findings are not directly equal to raw tool output. They are produced by
    evaluating evidence, potentially performing verification, and updating world model.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    description: str = ""
    category: FindingCategory = FindingCategory.WIRELESS
    severity: FindingSeverity = FindingSeverity.INFO
    status: FindingStatus = FindingStatus.HYPOTHESIS
    confidence: float = 0.5
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Evidence that supports this finding
    evidence_ids: List[str] = field(default_factory=list)
    # Identifiers related to finding (BSSID, SSID, IP, etc)
    affected_assets: List[str] = field(default_factory=list)
    # Structured data
    details: Dict[str, Any] = field(default_factory=dict)
    # Verification info
    verification_method: Optional[str] = None
    verified_at: Optional[datetime] = None
    verification_evidence_ids: List[str] = field(default_factory=list)
    # Audit
    tags: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.created_at.tzinfo is None:
            self.created_at = self.created_at.replace(tzinfo=timezone.utc)
        if self.updated_at.tzinfo is None:
            self.updated_at = self.updated_at.replace(tzinfo=timezone.utc)

    def add_evidence(self, evidence_id: str):
        if evidence_id not in self.evidence_ids:
            self.evidence_ids.append(evidence_id)
        self.updated_at = datetime.now(timezone.utc)

    def verify(self, verification_evidence_id: str, method: str):
        """Mark as verified with independent evidence."""
        self.status = FindingStatus.VERIFIED
        self.verification_method = method
        self.verified_at = datetime.now(timezone.utc)
        self.verification_evidence_ids.append(verification_evidence_id)
        self.confidence = max(self.confidence, 0.95)
        self.updated_at = datetime.now(timezone.utc)

    def support(self, evidence_id: str):
        """Add supporting evidence and potentially promote status."""
        self.add_evidence(evidence_id)
        if self.status == FindingStatus.HYPOTHESIS and len(self.evidence_ids) >= 2:
            self.status = FindingStatus.SUPPORTED
            self.confidence = max(self.confidence, 0.75)

    def refute(self, reason: str = ""):
        self.status = FindingStatus.REFUTED
        self.details["refutation_reason"] = reason
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "category": self.category.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "evidence_ids": self.evidence_ids,
            "affected_assets": self.affected_assets,
            "details": self.details,
            "verification_method": self.verification_method,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "verification_evidence_ids": self.verification_evidence_ids,
            "tags": self.tags,
        }
