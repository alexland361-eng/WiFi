"""
Verification Engine.

Decides whether observations and suspected findings are sufficiently supported
(specification section 8-10) and produces ``verification-result`` messages for the World Model.

It never executes a tool. When more evidence is needed it describes the requirement and returns
a ``VerificationActionRequest`` — an ordinary ``action-request`` — for the Decision Engine to
plan, validate and execute (specification section 9).

Decision procedure
------------------
For one claim the engine gathers every observation the World Model holds about the subject and
classifies it as supporting or contradicting, then applies the rules below in order. Each rule
that fires is recorded in ``conclusion.details``, so a reader can see *why* a conclusion was
reached rather than only what it was.

1. **Contradiction.** Evidence about the same subject asserting a different value for the
   claimed attribute is contradicting. If the contradicting side aggregates at least as much
   confidence as the supporting side, the claim is ``refuted``; if the two are close but
   neither is decisive, it is ``contradicted``.
2. **Freshness.** If every supporting observation is older than ``max_age_seconds``, the claim
   is ``stale``: the framework will not promote a conclusion it can no longer re-observe.
3. **Independence.** Distinct tools behind the supporting evidence. Two observations from one
   scan are one source, not two; counting them twice is how a transient radio observation
   becomes a fabricated finding.
4. **Aggregation.** Confidence of independent sources is combined with a noisy-OR,
   ``c = 1 - prod(1 - c_i)``, the standard combination under source independence.
5. **Conclusion.** ``verified`` when independence and the required confidence are both met;
   ``supported`` when confidence is met from a single source; otherwise ``unresolved`` with an
   explicit statement of the evidence still required.

The engine only ever *lowers* certainty on its own initiative. Raising a hypothesis to
``verified`` requires independent corroboration that already exists in the World Model.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ...contracts.action import ActionObjective, ActionRequest
from ...contracts.common import EntityRef, TargetType
from ...contracts.envelope import EngineId, format_timestamp, utc_now
from ...contracts.evidence import ObservationType
from ...contracts.verification import (
    Claim,
    ClaimType,
    EvidenceRequirement,
    VerificationConclusion,
    VerificationMethod,
    VerificationRequest,
    VerificationResult,
    VerificationStatus,
)
from ..models.assessment_state import AssessmentState
from ..models.evidence import Evidence
from ..models.finding import FindingCategory, FindingStatus

#: Contradiction margin: how much stronger one side must be to refute rather than contradict.
REFUTE_MARGIN = 0.10
#: Confidence within which two sides are considered too close to call.
CONTRADICT_TOLERANCE = 0.25

#: Claim type -> (observation type needed, capability categories that could produce it).
CLAIM_EVIDENCE_REQUIREMENTS: Dict[str, Tuple[str, List[str]]] = {
    ClaimType.WPS_STATE: (ObservationType.WPS, ["wps_discovery", "wireless_observation"]),
    ClaimType.ENCRYPTION_STATE: (ObservationType.ACCESS_POINT, ["wireless_observation", "packet_capture"]),
    ClaimType.HANDSHAKE_CAPTURED: (ObservationType.HANDSHAKE, ["wpa_assessment", "packet_capture"]),
    ClaimType.CREDENTIAL_RECOVERED: (ObservationType.CREDENTIAL, ["credential_assessment", "wpa_assessment"]),
    ClaimType.VULNERABILITY_PRESENT: (ObservationType.VULNERABILITY, ["vulnerability_assessment", "service_enumeration"]),
    ClaimType.ASSET_EXISTENCE: (ObservationType.ACCESS_POINT, ["wireless_observation", "network_discovery"]),
    ClaimType.ASSET_ATTRIBUTE: (ObservationType.ACCESS_POINT, ["wireless_observation", "packet_capture"]),
    ClaimType.HOST_REACHABLE: (ObservationType.NETWORK_HOST, ["network_discovery"]),
    ClaimType.SERVICE_PRESENT: (ObservationType.NETWORK_SERVICE, ["service_enumeration", "network_discovery"]),
    ClaimType.SECURITY_FINDING: (ObservationType.GENERIC, ["wireless_observation"]),
}

#: Finding category -> claim type used when verifying findings directly.
CATEGORY_CLAIMS: Dict[str, str] = {
    FindingCategory.WPS.value: ClaimType.WPS_STATE,
    FindingCategory.ENCRYPTION.value: ClaimType.ENCRYPTION_STATE,
    FindingCategory.AUTHENTICATION.value: ClaimType.HANDSHAKE_CAPTURED,
    FindingCategory.VULNERABILITY.value: ClaimType.VULNERABILITY_PRESENT,
    FindingCategory.NETWORK.value: ClaimType.HOST_REACHABLE,
    FindingCategory.SERVICE.value: ClaimType.SERVICE_PRESENT,
    FindingCategory.WIRELESS.value: ClaimType.ASSET_EXISTENCE,
    FindingCategory.CLIENT.value: ClaimType.ASSET_EXISTENCE,
    FindingCategory.CONFIGURATION.value: ClaimType.ASSET_ATTRIBUTE,
}


@dataclass
class VerificationOutcome:
    """A verification result plus any action requests needed to resolve it."""

    result: VerificationResult
    action_requests: List[ActionRequest] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def needs_more_evidence(self) -> bool:
        return bool(self.action_requests)

    def summary(self) -> Dict[str, Any]:
        return {
            "verification_id": self.result.verification_id,
            "status": self.result.status,
            "confidence": self.result.confidence,
            "independent_sources": list(self.result.independent_sources),
            "requested_actions": len(self.action_requests),
            "notes": list(self.notes),
        }


def noisy_or(confidences: Iterable[float]) -> float:
    """
    Combine independent confidences: ``1 - prod(1 - c_i)``.

    Two independent 0.7 observations combine to 0.91, which is the intended behaviour: repeated
    independent confirmation raises confidence, while repeating the *same* observation cannot
    (it is passed in once, because sources are de-duplicated by tool before aggregation).
    """
    complement = 1.0
    for value in confidences:
        try:
            complement *= 1.0 - max(0.0, min(1.0, float(value)))
        except (TypeError, ValueError):
            continue
    return round(1.0 - complement, 6)


class VerificationEngine:
    """Judges whether evidence sufficiently supports a claim."""

    def __init__(self, *, default_max_age_seconds: int = 600, default_min_sources: int = 2) -> None:
        self.default_max_age_seconds = default_max_age_seconds
        self.default_min_sources = default_min_sources

    # ------------------------------------------------------------------ public

    def verify(
        self, request: VerificationRequest, state: AssessmentState
    ) -> Optional[VerificationOutcome]:
        """
        Judge one ``verification-request`` against the current World Model.

        Returns ``None`` when the request cannot be judged at all (no resolvable subject), which
        the caller records rather than silently treating as a pass.
        """
        subject_id = request.subject.id or request.hypothesis_id
        if not subject_id:
            return None

        supporting, contradicting = self._gather(state, request, subject_id)
        if not supporting and not contradicting:
            return VerificationOutcome(
                result=self._result(
                    request,
                    status=VerificationStatus.UNRESOLVED,
                    subject_id=subject_id,
                    confidence=0.0,
                    supporting=[],
                    contradicting=[],
                    sources=[],
                    method=VerificationMethod.INSUFFICIENT_EVIDENCE,
                    details={"reason": "no evidence about this subject exists in the world model"},
                    state=state,
                ),
                action_requests=self._required_actions(request, subject_id, state),
                notes=["no evidence found for subject"],
            )

        details: Dict[str, Any] = {}
        notes: List[str] = []

        support_confidence = noisy_or(evidence.confidence for evidence in supporting)
        contradict_confidence = noisy_or(evidence.confidence for evidence in contradicting)
        sources = sorted({evidence.source.tool_name for evidence in supporting if evidence.source.tool_name})
        details.update(
            {
                "supporting_count": len(supporting),
                "contradicting_count": len(contradicting),
                "independent_sources": sources,
                "aggregated_support_confidence": support_confidence,
                "aggregated_contradiction_confidence": contradict_confidence,
                "required_confidence": request.required_confidence,
                "min_independent_sources": request.min_independent_sources,
            }
        )

        # 1. contradiction ----------------------------------------------------
        if contradicting:
            if contradict_confidence >= support_confidence + REFUTE_MARGIN:
                details["reason"] = (
                    f"contradicting evidence ({contradict_confidence}) outweighs supporting "
                    f"evidence ({support_confidence}) by more than {REFUTE_MARGIN}"
                )
                details["contradiction"] = self._contradiction_summary(contradicting, request)
                return VerificationOutcome(
                    result=self._result(
                        request,
                        status=VerificationStatus.REFUTED,
                        subject_id=subject_id,
                        confidence=contradict_confidence,
                        supporting=supporting,
                        contradicting=contradicting,
                        sources=sources,
                        method=VerificationMethod.CONTRADICTION_DETECTION,
                        details=details,
                        state=state,
                    ),
                    notes=["claim refuted by contradicting evidence"],
                )
            if abs(contradict_confidence - support_confidence) <= CONTRADICT_TOLERANCE:
                details["reason"] = (
                    "supporting and contradicting evidence are too close to call "
                    f"({support_confidence} vs {contradict_confidence})"
                )
                details["contradiction"] = self._contradiction_summary(contradicting, request)
                outcome = self._result(
                    request,
                    status=VerificationStatus.CONTRADICTED,
                    subject_id=subject_id,
                    confidence=max(support_confidence, contradict_confidence) / 2.0,
                    supporting=supporting,
                    contradicting=contradicting,
                    sources=sources,
                    method=VerificationMethod.CONTRADICTION_DETECTION,
                    details=details,
                    state=state,
                )
                return VerificationOutcome(
                    result=outcome,
                    action_requests=self._required_actions(request, subject_id, state),
                    notes=["conflicting evidence; additional observation required"],
                )
            notes.append(
                "contradicting evidence exists but is weaker than supporting evidence; "
                "it is recorded, not acted on"
            )

        # 2. freshness --------------------------------------------------------
        max_age = request.max_age_seconds or self.default_max_age_seconds
        newest = self._newest(supporting)
        if newest is not None:
            age_seconds = (utc_now() - newest).total_seconds()
            details["newest_support_age_seconds"] = round(age_seconds, 3)
            details["max_age_seconds"] = max_age
            if supporting and age_seconds > max_age:
                details["reason"] = (
                    f"all supporting evidence is older than {max_age}s (newest is {age_seconds:.0f}s old)"
                )
                return VerificationOutcome(
                    result=self._result(
                        request,
                        status=VerificationStatus.STALE,
                        subject_id=subject_id,
                        confidence=support_confidence,
                        supporting=supporting,
                        contradicting=contradicting,
                        sources=sources,
                        method=VerificationMethod.FRESHNESS_CHECK,
                        details=details,
                        state=state,
                    ),
                    action_requests=self._required_actions(request, subject_id, state),
                    notes=["supporting evidence is stale"],
                )

        # 3-5. independence, aggregation, conclusion --------------------------
        min_sources = request.min_independent_sources or self.default_min_sources
        if len(sources) >= min_sources and support_confidence >= request.required_confidence:
            details["reason"] = (
                f"{len(sources)} independent sources ({', '.join(sources)}) aggregate to "
                f"{support_confidence}, meeting the required {request.required_confidence}"
            )
            status = VerificationStatus.VERIFIED
            method = VerificationMethod.MULTI_TOOL_CORRELATION
        elif support_confidence >= request.required_confidence:
            details["reason"] = (
                f"confidence {support_confidence} meets the threshold but only "
                f"{len(sources)} independent source(s) exist; {min_sources} required for 'verified'"
            )
            status = VerificationStatus.SUPPORTED
            method = (
                VerificationMethod.REPEATED_OBSERVATION
                if len(supporting) > 1
                else VerificationMethod.CONFIDENCE_AGGREGATION
            )
        else:
            details["reason"] = (
                f"aggregated confidence {support_confidence} is below the required "
                f"{request.required_confidence} with {len(sources)} independent source(s)"
            )
            status = VerificationStatus.UNRESOLVED
            method = VerificationMethod.INSUFFICIENT_EVIDENCE

        result = self._result(
            request,
            status=status,
            subject_id=subject_id,
            confidence=support_confidence,
            supporting=supporting,
            contradicting=contradicting,
            sources=sources,
            method=method,
            details=details,
            state=state,
        )
        return VerificationOutcome(
            result=result,
            action_requests=self._required_actions(request, subject_id, state)
            if status in VerificationStatus.INSUFFICIENT
            else [],
            notes=notes,
        )

    def verify_open_findings(
        self, state: AssessmentState, *, limit: Optional[int] = None
    ) -> List[VerificationOutcome]:
        """
        Build verification requests for findings that are still open questions and judge them.

        This replaces the ad-hoc multi-tool correlation previously inlined in the assessment
        engine with the same rule set used for evidence-driven claims.
        """
        outcomes: List[VerificationOutcome] = []
        open_findings = [
            finding
            for finding in state.findings
            if finding.status in (FindingStatus.HYPOTHESIS, FindingStatus.SUPPORTED, FindingStatus.UNRESOLVED)
        ]
        for finding in open_findings[:limit] if limit else open_findings:
            request = self.request_for_finding(finding, state)
            outcome = self.verify(request, state)
            if outcome is not None:
                outcomes.append(outcome)
        return outcomes

    def request_for_finding(
        self, finding: Any, state: AssessmentState, *, verification_id: Optional[str] = None
    ) -> VerificationRequest:
        """Derive a ``verification-request`` from an existing finding."""
        category = finding.category.value if hasattr(finding.category, "value") else str(finding.category)
        claim_type = CATEGORY_CLAIMS.get(category, ClaimType.SECURITY_FINDING)
        subject_id = (finding.affected_assets or [None])[0]
        required_confidence = self._required_confidence_for(finding, claim_type)
        tools = sorted(
            {
                evidence.source.tool_name
                for evidence in state.evidences
                if evidence.id in (finding.evidence_ids or [])
            }
        )
        return VerificationRequest(
            assessment_id=state.id,
            source_engine=EngineId.WORLD_MODEL.value,
            verification_id=verification_id or f"verification-{finding.id[:12]}",
            subject=EntityRef(
                type=TargetType.ACCESS_POINT.value if subject_id and ":" in str(subject_id) else TargetType.FINDING.value,
                id=subject_id or finding.id,
            ),
            claim=Claim(type=claim_type, description=finding.title or finding.description),
            supporting_evidence=list(finding.evidence_ids or []),
            required_confidence=required_confidence,
            max_age_seconds=self.default_max_age_seconds,
            min_independent_sources=2 if claim_type != ClaimType.ASSET_EXISTENCE else 1,
            hypothesis_id=finding.id,
        )

    # ---------------------------------------------------------------- internals

    @staticmethod
    def _required_confidence_for(finding: Any, claim_type: str) -> float:
        """
        Confidence a finding must reach to be verified.

        Severity drives the bar: a critical claim needs stronger evidence than an informational
        one, because the cost of being wrong is higher.
        """
        severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        table = {"critical": 0.95, "high": 0.90, "medium": 0.85, "low": 0.80, "info": 0.75}
        return table.get(severity, 0.85)

    def _gather(
        self, state: AssessmentState, request: VerificationRequest, subject_id: str
    ) -> Tuple[List[Evidence], List[Evidence]]:
        """Split the World Model's evidence about this subject into supporting and contradicting."""
        claimed_ids = set(request.supporting_evidence) | set(request.contradicting_evidence)
        attribute = request.claim.attribute if request.claim else None
        expected = request.claim.expected_value if request.claim else None

        candidates: List[Evidence] = []
        for evidence in state.evidences:
            if evidence.id in claimed_ids:
                candidates.append(evidence)
                continue
            if self._about_subject(evidence, subject_id):
                candidates.append(evidence)

        supporting: List[Evidence] = []
        contradicting: List[Evidence] = []
        for evidence in candidates:
            if evidence.id in request.contradicting_evidence:
                contradicting.append(evidence)
                continue
            if attribute is None:
                supporting.append(evidence)
                continue
            observed = self._observed_value(evidence, attribute)
            if observed is None:
                # Evidence that says nothing about the claimed attribute supports the subject's
                # existence but not the attribute; it is neither supporting nor contradicting.
                continue
            if self._values_agree(observed, expected):
                supporting.append(evidence)
            else:
                contradicting.append(evidence)
        return supporting, contradicting

    @staticmethod
    def _about_subject(evidence: Evidence, subject_id: str) -> bool:
        data = evidence.parsed_data or {}
        for key in ("bssid", "mac", "client_mac", "ap_mac", "ip", "target_ip", "name", "domain", "hostname"):
            value = data.get(key)
            if value and str(value).upper() == str(subject_id).upper():
                return True
        if evidence.interface and str(evidence.interface) == str(subject_id):
            return True
        return False

    @staticmethod
    def _observed_value(evidence: Evidence, attribute: str) -> Any:
        data = evidence.parsed_data or {}
        if attribute in data:
            return data[attribute]
        return None

    @staticmethod
    def _values_agree(observed: Any, expected: Any) -> bool:
        """Compare an observed value with the claimed one, tolerating list/bool/str variation."""
        if expected is None:
            return True
        if isinstance(expected, bool) or isinstance(observed, bool):
            return bool(observed) == bool(expected)
        if isinstance(expected, (list, tuple, set)) or isinstance(observed, (list, tuple, set)):
            expected_set = {str(item).upper() for item in (expected or [])}
            observed_set = {str(item).upper() for item in (observed or [])}
            # Agreement means the observation contains what was claimed.
            return expected_set.issubset(observed_set) or bool(expected_set & observed_set)
        return str(observed).upper() == str(expected).upper()

    @staticmethod
    def _newest(evidences: Sequence[Evidence]) -> Optional[datetime]:
        stamps = [
            evidence.timestamp if evidence.timestamp.tzinfo else evidence.timestamp.replace(tzinfo=timezone.utc)
            for evidence in evidences
            if evidence.timestamp is not None
        ]
        return max(stamps) if stamps else None

    @staticmethod
    def _contradiction_summary(contradicting: Sequence[Evidence], request: VerificationRequest) -> List[Dict[str, Any]]:
        attribute = request.claim.attribute if request.claim else None
        summary = []
        for evidence in contradicting[:10]:
            summary.append(
                {
                    "evidence_id": evidence.id,
                    "tool": evidence.source.tool_name,
                    "timestamp": format_timestamp(evidence.timestamp),
                    "observed": evidence.parsed_data.get(attribute) if attribute else None,
                    "confidence": evidence.confidence,
                }
            )
        return summary

    def _result(
        self,
        request: VerificationRequest,
        *,
        status: str,
        subject_id: str,
        confidence: float,
        supporting: Sequence[Evidence],
        contradicting: Sequence[Evidence],
        sources: Sequence[str],
        method: str,
        details: Dict[str, Any],
        state: AssessmentState,
    ) -> VerificationResult:
        details = dict(details)
        details["claim"] = request.claim.to_dict() if request.claim else None
        details["subject_id"] = subject_id
        required = self._required_evidence(request, subject_id, state) if status in VerificationStatus.INSUFFICIENT else []
        if required:
            details["required_evidence"] = [item.to_dict() for item in required]
        return VerificationResult(
            assessment_id=request.assessment_id,
            source_engine=EngineId.VERIFICATION.value,
            correlation_id=request.correlation_id,
            verification_id=request.verification_id,
            status=status,
            subject_id=subject_id,
            confidence=round(max(0.0, min(1.0, float(confidence))), 6),
            supporting_evidence=[evidence.id for evidence in supporting],
            contradicting_evidence=[evidence.id for evidence in contradicting],
            conclusion=VerificationConclusion(state=status, details=details),
            method=method,
            independent_sources=list(sources),
            required_evidence=required,
            hypothesis_id=request.hypothesis_id,
            claim=request.claim,
            verified_at=format_timestamp(utc_now()),
            action_id=request.action_id,
            execution_id=request.execution_id,
            required_confidence=request.required_confidence,
        )

    @staticmethod
    def _required_evidence(
        request: VerificationRequest, subject_id: str, state: AssessmentState
    ) -> List[EvidenceRequirement]:
        """State precisely what is still missing, without choosing a tool."""
        claim_type = request.claim.type if request.claim else ClaimType.SECURITY_FINDING
        observation_type, capabilities = CLAIM_EVIDENCE_REQUIREMENTS.get(
            claim_type, (ObservationType.GENERIC, ["wireless_observation"])
        )
        known_sources = {
            evidence.source.tool_name
            for evidence in state.evidences
            if evidence.id in set(request.supporting_evidence)
        }
        description = (
            f"a '{observation_type}' observation about {subject_id} from a source other than "
            f"{sorted(known_sources) or 'any already used'}"
        )
        return [
            EvidenceRequirement(
                observation_type=observation_type,
                subject_id=subject_id,
                description=description,
                candidate_capabilities=list(capabilities),
            )
        ]

    def _required_actions(
        self, request: VerificationRequest, subject_id: str, state: AssessmentState
    ) -> List[ActionRequest]:
        """
        Build the VerificationActionRequest(s) the Decision Engine should plan next.

        Only the capability *category* is named here. Which real tool implements it, and against
        which interface, is the Decision Engine's and Execution Engine's decision.
        """
        import uuid

        requirements = self._required_evidence(request, subject_id, state)
        subject_type = request.subject.type if request.subject else TargetType.NONE.value
        actions: List[ActionRequest] = []
        for requirement in requirements:
            for capability in requirement.candidate_capabilities:
                actions.append(
                    ActionRequest.for_verification(
                        assessment_id=request.assessment_id,
                        action_id=str(uuid.uuid4()),
                        verification_id=request.verification_id,
                        capability=capability,
                        target=EntityRef(type=subject_type, id=subject_id),
                        parameters=self._hint_parameters(request, subject_id),
                        expected_outputs=[requirement.observation_type],
                        information_gaps=[request.verification_id],
                        supporting_evidence=list(request.supporting_evidence),
                        summary=requirement.description,
                        correlation_id=request.correlation_id,
                        source_engine=EngineId.VERIFICATION.value,
                    )
                )
        return actions

    @staticmethod
    def _hint_parameters(request: VerificationRequest, subject_id: str) -> Dict[str, Any]:
        """
        Parameter hints derived from the claim, never a command.

        Hints keep the follow-up observation aimed at the same subject; the Execution Engine
        still derives and validates the real parameters from assessment state.
        """
        subject_type = request.subject.type if request.subject else None
        if subject_type == TargetType.ACCESS_POINT.value and ":" in str(subject_id):
            return {"bssid": subject_id}
        if subject_type == TargetType.HOST.value:
            return {"target_ip": subject_id}
        if subject_type == TargetType.INTERFACE.value:
            return {"interface": subject_id}
        return {}
