"""
``verification-request`` and ``verification-result`` contracts (version 1.0).

Producer of ``verification-request``: Evidence Engine / World Model. Consumer: Verification.
Producer of ``verification-result``: Verification Engine. Consumer: World Model.

The Verification Engine decides whether supplied evidence is sufficient or whether more
evidence must be obtained. When more evidence is needed it does **not** execute a tool: it
describes the requirement in ``VerificationResult.required_evidence`` and the orchestrator
asks the Decision Engine for a ``VerificationActionRequest`` (see
:meth:`wifi_framework.contracts.action.ActionRequest.for_verification`).

The result states are the six listed in specification section 10. Their meaning here is
deliberately narrow, because transient wireless observations must not become findings:

``verified``      independent corroboration reached the required confidence
``supported``     single-source evidence, plausible but not independently confirmed
``unresolved``    not enough evidence either way; more is required
``contradicted``  evidence conflicts, and neither side is strong enough to win
``refuted``       conflicting evidence decisively favours the opposite claim
``stale``         the supporting evidence is older than the freshness window
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .base import BaseContract
from .common import EntityRef, TargetType, to_jsonable
from .envelope import EngineId
from .validation import (
    ValidationIssue,
    ValidationLevel,
    require_confidence,
    require_enum,
    require_type,
)


class VerificationStatus:
    """Conclusion states from specification section 10."""

    VERIFIED = "verified"
    SUPPORTED = "supported"
    UNRESOLVED = "unresolved"
    CONTRADICTED = "contradicted"
    REFUTED = "refuted"
    STALE = "stale"

    ALL: List[str] = [VERIFIED, SUPPORTED, UNRESOLVED, CONTRADICTED, REFUTED, STALE]
    #: Conclusions that let the World Model promote a hypothesis.
    POSITIVE: List[str] = [VERIFIED, SUPPORTED]
    #: Conclusions that must stop a hypothesis being reported as a finding.
    NEGATIVE: List[str] = [CONTRADICTED, REFUTED]
    #: Conclusions that need more evidence before any promotion.
    INSUFFICIENT: List[str] = [UNRESOLVED, STALE]


class ClaimType:
    """Kinds of claim that can be verified."""

    SECURITY_FINDING = "security_finding"
    ASSET_EXISTENCE = "asset_existence"
    ASSET_ATTRIBUTE = "asset_attribute"
    WPS_STATE = "wps_state"
    ENCRYPTION_STATE = "encryption_state"
    HANDSHAKE_CAPTURED = "handshake_captured"
    CREDENTIAL_RECOVERED = "credential_recovered"
    HOST_REACHABLE = "host_reachable"
    SERVICE_PRESENT = "service_present"
    VULNERABILITY_PRESENT = "vulnerability_present"

    ALL: List[str] = [
        SECURITY_FINDING,
        ASSET_EXISTENCE,
        ASSET_ATTRIBUTE,
        WPS_STATE,
        ENCRYPTION_STATE,
        HANDSHAKE_CAPTURED,
        CREDENTIAL_RECOVERED,
        HOST_REACHABLE,
        SERVICE_PRESENT,
        VULNERABILITY_PRESENT,
    ]


class VerificationMethod:
    """How a conclusion was reached. Recorded in the audit trail."""

    MULTI_TOOL_CORRELATION = "multi_tool_correlation"
    REPEATED_OBSERVATION = "repeated_observation"
    CONFIDENCE_AGGREGATION = "confidence_aggregation"
    CONTRADICTION_DETECTION = "contradiction_detection"
    FRESHNESS_CHECK = "freshness_check"
    INDEPENDENT_OPERATION = "independent_operation"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"

    ALL: List[str] = [
        MULTI_TOOL_CORRELATION,
        REPEATED_OBSERVATION,
        CONFIDENCE_AGGREGATION,
        CONTRADICTION_DETECTION,
        FRESHNESS_CHECK,
        INDEPENDENT_OPERATION,
        INSUFFICIENT_EVIDENCE,
    ]


@dataclass(frozen=True)
class Claim:
    """The assertion under verification."""

    type: str
    description: str
    #: Expected value, when the claim asserts a specific attribute (e.g. ``wps_enabled: true``).
    attribute: Optional[str] = None
    expected_value: Any = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "description": self.description,
            "attribute": self.attribute,
            "expected_value": to_jsonable(self.expected_value),
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "Claim":
        data = data or {}
        return cls(
            type=str(data.get("type") or ClaimType.SECURITY_FINDING),
            description=str(data.get("description") or ""),
            attribute=data.get("attribute"),
            expected_value=data.get("expected_value"),
        )


@dataclass(frozen=True)
class VerificationRequirement:
    """One condition the evidence must satisfy for the claim to be accepted."""

    type: str
    value: Any = None
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.type, "value": to_jsonable(self.value), "description": self.description}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VerificationRequirement":
        return cls(
            type=str(data.get("type")),
            value=data.get("value"),
            description=str(data.get("description") or ""),
        )


@dataclass(kw_only=True)
class VerificationRequest(BaseContract):
    """A request to judge whether evidence sufficiently supports a claim."""

    SCHEMA = "verification-request"
    VERSION = "1.0"
    PRODUCER = EngineId.EVIDENCE.value
    REQUIRED_PAYLOAD_FIELDS = ("verification_id", "subject", "claim")

    verification_id: str
    subject: EntityRef
    claim: Claim
    supporting_evidence: List[str] = field(default_factory=list)
    required_confidence: float = 0.90
    verification_requirements: List[VerificationRequirement] = field(default_factory=list)

    #: Optional extensions ---------------------------------------------------
    #: Hypothesis/finding this request concerns, when the subject is an asset.
    hypothesis_id: Optional[str] = None
    #: Evidence that argues against the claim, if already known.
    contradicting_evidence: List[str] = field(default_factory=list)
    #: Freshness window in seconds for the supporting evidence.
    max_age_seconds: Optional[int] = None
    #: Minimum number of distinct tools required for ``verified``.
    min_independent_sources: int = 2
    #: Action that produced the supporting evidence (correlation chain).
    action_id: Optional[str] = None
    execution_id: Optional[str] = None

    @classmethod
    def _coerce_payload(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        coerced = dict(payload)
        if isinstance(coerced.get("subject"), dict):
            coerced["subject"] = EntityRef.from_dict(coerced["subject"])
        if isinstance(coerced.get("claim"), dict):
            coerced["claim"] = Claim.from_dict(coerced["claim"])
        requirements = coerced.get("verification_requirements")
        if isinstance(requirements, list) and requirements and isinstance(requirements[0], dict):
            coerced["verification_requirements"] = [
                VerificationRequirement.from_dict(item) for item in requirements
            ]
        return coerced

    def extra_structural_issues(self, payload: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        issues.extend(require_confidence(payload, "required_confidence"))
        issues.extend(require_type(payload, "supporting_evidence", list))
        min_sources = payload.get("min_independent_sources")
        if min_sources is not None and (not isinstance(min_sources, int) or isinstance(min_sources, bool) or min_sources < 1):
            issues.append(
                ValidationIssue(
                    level=ValidationLevel.STRUCTURAL.value,
                    code="out_of_range",
                    message=f"min_independent_sources must be an integer >= 1, got {min_sources!r}",
                    field="min_independent_sources",
                )
            )
        claim = payload.get("claim")
        claim_type = claim.type if isinstance(claim, Claim) else (claim or {}).get("type")
        if claim_type and claim_type not in ClaimType.ALL:
            issues.append(
                ValidationIssue(
                    level=ValidationLevel.STRUCTURAL.value,
                    code="invalid_enum_value",
                    message=f"claim.type '{claim_type}' is not a known claim type",
                    field="claim.type",
                    details={"allowed": ClaimType.ALL},
                )
            )
        return issues


@dataclass(frozen=True)
class EvidenceRequirement:
    """
    Evidence still needed before the claim can be resolved.

    This is the structured input the Decision Engine turns into a VerificationActionRequest;
    it names what is missing without naming a tool, so tool choice stays with the planner.
    """

    observation_type: str
    subject_id: Optional[str] = None
    description: str = ""
    #: Capability categories that could produce it, e.g. ``wireless_observation``.
    candidate_capabilities: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "observation_type": self.observation_type,
            "subject_id": self.subject_id,
            "description": self.description,
            "candidate_capabilities": list(self.candidate_capabilities),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceRequirement":
        return cls(
            observation_type=str(data.get("observation_type") or "generic"),
            subject_id=data.get("subject_id"),
            description=str(data.get("description") or ""),
            candidate_capabilities=list(data.get("candidate_capabilities") or []),
        )


@dataclass(frozen=True)
class VerificationConclusion:
    """The ``conclusion`` object of a VerificationResult."""

    state: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"state": self.state, "details": to_jsonable(self.details)}

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "VerificationConclusion":
        data = data or {}
        return cls(state=str(data.get("state") or VerificationStatus.UNRESOLVED), details=dict(data.get("details") or {}))


@dataclass(kw_only=True)
class VerificationResult(BaseContract):
    """The Verification Engine's judgement about one claim."""

    SCHEMA = "verification-result"
    VERSION = "1.0"
    PRODUCER = EngineId.VERIFICATION.value
    REQUIRED_PAYLOAD_FIELDS = ("verification_id", "status", "subject_id", "conclusion")

    verification_id: str
    status: str
    subject_id: Optional[str]
    confidence: float
    supporting_evidence: List[str] = field(default_factory=list)
    contradicting_evidence: List[str] = field(default_factory=list)
    conclusion: VerificationConclusion

    #: Optional extensions ---------------------------------------------------
    method: Optional[str] = None
    #: Distinct tools behind the supporting evidence (independence evidence).
    independent_sources: List[str] = field(default_factory=list)
    #: What is still missing when the conclusion is unresolved or stale.
    required_evidence: List[EvidenceRequirement] = field(default_factory=list)
    #: Hypothesis/finding updated by this result.
    hypothesis_id: Optional[str] = None
    claim: Optional[Claim] = None
    verified_at: Optional[str] = None
    #: Correlation to the action whose evidence triggered this verification.
    action_id: Optional[str] = None
    execution_id: Optional[str] = None
    required_confidence: Optional[float] = None

    @classmethod
    def _coerce_payload(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        coerced = dict(payload)
        if isinstance(coerced.get("conclusion"), dict):
            coerced["conclusion"] = VerificationConclusion.from_dict(coerced["conclusion"])
        if isinstance(coerced.get("claim"), dict):
            coerced["claim"] = Claim.from_dict(coerced["claim"])
        required = coerced.get("required_evidence")
        if isinstance(required, list) and required and isinstance(required[0], dict):
            coerced["required_evidence"] = [EvidenceRequirement.from_dict(item) for item in required]
        return coerced

    def extra_structural_issues(self, payload: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        issues.extend(require_enum(payload, "status", VerificationStatus.ALL))
        issues.extend(require_confidence(payload, "confidence"))
        issues.extend(require_confidence(payload, "required_confidence"))
        method = payload.get("method")
        if method and method not in VerificationMethod.ALL:
            issues.append(
                ValidationIssue(
                    level=ValidationLevel.STRUCTURAL.value,
                    code="invalid_enum_value",
                    message=f"method '{method}' is not a known verification method",
                    field="method",
                    details={"allowed": VerificationMethod.ALL},
                )
            )
        conclusion = payload.get("conclusion")
        state = conclusion.state if isinstance(conclusion, VerificationConclusion) else (conclusion or {}).get("state")
        if state and state not in VerificationStatus.ALL:
            issues.append(
                ValidationIssue(
                    level=ValidationLevel.STRUCTURAL.value,
                    code="invalid_enum_value",
                    message=f"conclusion.state '{state}' is not a known verification status",
                    field="conclusion.state",
                    details={"allowed": VerificationStatus.ALL},
                )
            )
        return issues

    def contextual_issues(self, level) -> List[ValidationIssue]:
        from .validation import ValidationLevel

        if level != ValidationLevel.SEMANTIC:
            return []
        issues: List[ValidationIssue] = []
        # ``verified`` requires genuine independence; without it the honest state is
        # ``supported``. This is the rule that stops one scan being counted twice.
        if self.status == VerificationStatus.VERIFIED and len(self.independent_sources) < 2:
            issues.append(
                ValidationIssue(
                    level="semantic",
                    code="verified_without_independence",
                    message=f"status 'verified' requires >= 2 independent sources, got {self.independent_sources}",
                    field="independent_sources",
                )
            )
        if self.status == VerificationStatus.VERIFIED and self.required_confidence is not None:
            if self.confidence < self.required_confidence:
                issues.append(
                    ValidationIssue(
                        level="semantic",
                        code="confidence_below_threshold",
                        message=f"confidence {self.confidence} is below required {self.required_confidence}",
                        field="confidence",
                    )
                )
        if self.status in VerificationStatus.INSUFFICIENT and not self.required_evidence:
            issues.append(
                ValidationIssue(
                    level="semantic",
                    code="missing_required_evidence",
                    message=f"status '{self.status}' must state which evidence is still required",
                    field="required_evidence",
                )
            )
        if self.status in VerificationStatus.NEGATIVE and not self.contradicting_evidence:
            issues.append(
                ValidationIssue(
                    level="semantic",
                    code="missing_contradiction",
                    message=f"status '{self.status}' must cite contradicting evidence",
                    field="contradicting_evidence",
                )
            )
        if self.conclusion.state != self.status:
            issues.append(
                ValidationIssue(
                    level="semantic",
                    code="conclusion_mismatch",
                    message=f"conclusion.state '{self.conclusion.state}' disagrees with status '{self.status}'",
                    field="conclusion.state",
                )
            )
        return issues

    # ------------------------------------------------------------------ helpers

    @property
    def positive(self) -> bool:
        return self.status in VerificationStatus.POSITIVE

    @property
    def needs_more_evidence(self) -> bool:
        return self.status in VerificationStatus.INSUFFICIENT and bool(self.required_evidence)

    @property
    def subject_ref(self) -> EntityRef:
        return EntityRef(type=TargetType.HYPOTHESIS.value, id=self.subject_id)
