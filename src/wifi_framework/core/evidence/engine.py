"""
Evidence Engine.

Receives the real execution result and its artifacts and determines what *observable
information* can legitimately be extracted (specification section 6). It produces the
``evidence-set`` contract for the World Model and ``verification-request`` contracts for the
Verification Engine.

Three rules shape this module:

1. **Provenance is preserved back to the originating action.** Every observation carries
   ``execution_id``, ``action_id``, the tool, the interface, the recorded command and the
   artifacts it was derived from.
2. **Raw output is never a finding.** The engine emits observations and *requests*
   verification for significant ones; it never promotes anything itself.
3. **Nothing is fabricated and nothing is hidden.** If a tool failed, timed out or produced
   output the parser could not fully interpret, that is recorded in ``parse_issues`` and
   ``incomplete`` rather than being presented as a clean result. Partial output from an
   interrupted capture is still real evidence, so it is kept and flagged.

The engine does not re-parse tool output. Adapters own parsing (they are the components with
tool-specific knowledge); this engine normalises, scopes, attributes and judges what the
parsed output means for the rest of the framework. That keeps one parser per tool instead of
two disagreeing ones.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ...contracts.common import ArtifactRef, ParserRef, Provenance, EntityRef, TargetType
from ...contracts.envelope import EngineId, format_timestamp, utc_now
from ...contracts.evidence import EvidenceSet, Observation, ObservationType
from ...contracts.execution import ExecutionResult, ExecutionStatus
from ...contracts.verification import (
    Claim,
    ClaimType,
    VerificationMethod,
    VerificationRequest,
    VerificationRequirement,
)
from ..models.evidence import Evidence
from ..models.scope import AssessmentScope, ScopeEnforcer

#: Observation types that must be confirmed before they may become findings.
SIGNIFICANT_TYPES: Tuple[str, ...] = (
    ObservationType.VULNERABILITY,
    ObservationType.CREDENTIAL,
    ObservationType.HANDSHAKE,
    ObservationType.WPS,
)

#: Claim type, required confidence and independence needed per significant observation.
VERIFICATION_POLICY: Dict[str, Dict[str, Any]] = {
    ObservationType.VULNERABILITY: {
        "claim": ClaimType.VULNERABILITY_PRESENT,
        "required_confidence": 0.95,
        "min_independent_sources": 2,
        "description": "tool-reported vulnerability requires independent confirmation",
    },
    ObservationType.CREDENTIAL: {
        "claim": ClaimType.CREDENTIAL_RECOVERED,
        "required_confidence": 0.95,
        "min_independent_sources": 2,
        "description": "recovered credential material requires independent confirmation",
    },
    ObservationType.HANDSHAKE: {
        "claim": ClaimType.HANDSHAKE_CAPTURED,
        "required_confidence": 0.90,
        "min_independent_sources": 2,
        "description": "captured handshake requires conversion/verification by a second tool",
    },
    ObservationType.WPS: {
        "claim": ClaimType.WPS_STATE,
        "required_confidence": 0.85,
        "min_independent_sources": 2,
        "description": "WPS state requires corroboration by a second observation source",
    },
}

#: Encryption values that make an access point a weak-encryption claim.
WEAK_ENCRYPTION = {"WEP", "WPA", "WPA1", "TKIP", "", "OPN"}


@dataclass
class EvidenceProcessingResult:
    """
    What the Evidence Engine produced for one execution.

    ``evidences`` carries the model-layer objects that correspond one-to-one with
    ``evidence_set.observations``; the World Model applier needs both (see
    :mod:`wifi_framework.core.world.applier`).
    """

    evidence_set: EvidenceSet
    evidences: List[Evidence] = field(default_factory=list)
    verification_requests: List[VerificationRequest] = field(default_factory=list)
    #: Observations dropped because they could not be attributed to a subject.
    dropped: List[str] = field(default_factory=list)

    def summary(self) -> Dict[str, Any]:
        return {
            "observations": len(self.evidence_set.observations),
            "verification_requests": len(self.verification_requests),
            "parse_issues": list(self.evidence_set.parse_issues),
            "incomplete": self.evidence_set.incomplete,
            "dropped": list(self.dropped),
        }


def new_verification_id() -> str:
    """Stable-format identifier for a verification cycle."""
    import uuid

    return f"verification-{uuid.uuid4().hex[:12]}"


class EvidenceEngine:
    """Turns execution results into scoped, attributed, verifiable observations."""

    def __init__(
        self,
        scope: Optional[AssessmentScope] = None,
        *,
        parser_name: str = "adapter-parsers",
        parser_version: str = "1.0",
        max_age_seconds: int = 600,
    ) -> None:
        self.scope = scope
        self.enforcer = ScopeEnforcer(scope) if scope is not None else None
        self.parser_name = parser_name
        self.parser_version = parser_version
        self.max_age_seconds = max_age_seconds
        #: (subject_id, claim_type) -> verification_id, so repeated observations of the same
        #: claim reuse one verification cycle instead of spawning duplicates.
        self._verification_ids: Dict[Tuple[str, str], str] = {}

    # ------------------------------------------------------------------ public

    def process(
        self,
        execution: ExecutionResult,
        evidences: Sequence[Evidence],
        *,
        action_id: Optional[str] = None,
        capability: Optional[str] = None,
        scope: Optional[AssessmentScope] = None,
    ) -> EvidenceProcessingResult:
        """Build the ``evidence-set`` for one execution result."""
        effective_scope = scope or self.scope
        enforcer = ScopeEnforcer(effective_scope) if effective_scope is not None else self.enforcer
        parse_issues: List[str] = []
        observations: List[Observation] = []
        kept: List[Evidence] = []
        dropped: List[str] = []
        artifact_ids = [artifact.id for artifact in execution.artifacts]

        parse_issues.extend(self._execution_issues(execution))

        for evidence in evidences:
            observation = self._observation(
                evidence=evidence,
                execution=execution,
                action_id=action_id or execution.action_id,
                artifact_ids=artifact_ids,
                enforcer=enforcer,
            )
            if observation is None:
                dropped.append(evidence.id)
                parse_issues.append(
                    f"observation {evidence.id} ({evidence.evidence_type.value}) could not be "
                    "attributed to a subject and was not added to the world model"
                )
                continue
            if not evidence.parsed_data:
                parse_issues.append(
                    f"observation {evidence.id} carried no parsed data; recorded as unstructured"
                )
                observation = self._mark_partial(observation)
            observations.append(observation)
            kept.append(evidence)

        evidence_set = EvidenceSet(
            assessment_id=execution.assessment_id,
            source_engine=EngineId.EVIDENCE.value,
            correlation_id=execution.correlation_id,
            action_id=action_id or execution.action_id,
            execution_id=execution.execution_id,
            observations=observations,
            artifacts=list(execution.artifacts),
            parser=ParserRef(name=self.parser_name, version=self.parser_version),
            capability=capability or execution.capability,
            tool=execution.tool.name if execution.tool else None,
            parse_issues=parse_issues,
            # A timeout yields only what the tool produced before it was stopped, so its output
            # is incomplete just as an explicitly partial run is.
            incomplete=execution.status in (ExecutionStatus.PARTIAL, ExecutionStatus.TIMEOUT)
            or bool(dropped),
        )

        requests = self._verification_requests(evidence_set, execution)
        return EvidenceProcessingResult(
            evidence_set=evidence_set,
            evidences=kept,
            verification_requests=requests,
            dropped=dropped,
        )

    # ---------------------------------------------------------------- internals

    @staticmethod
    def _execution_issues(execution: ExecutionResult) -> List[str]:
        """Record what the execution itself tells us about the trustworthiness of its output."""
        issues: List[str] = []
        if execution.status == ExecutionStatus.TIMEOUT:
            issues.append(
                "execution timed out; output is partial and reflects only what the tool "
                "produced before it was stopped"
            )
        elif execution.status == ExecutionStatus.PARTIAL:
            issues.append("execution reported partial completion; observations may be incomplete")
        elif execution.status in (ExecutionStatus.FAILED, ExecutionStatus.CANCELLED):
            failure = execution.failure
            issues.append(
                f"execution status was '{execution.status}'"
                + (f" ({failure.category}: {failure.message})" if failure else "")
                + "; any observations are taken from a failed run"
            )
        elif execution.status in ExecutionStatus.TERMINAL_NOT_EXECUTED:
            failure = execution.failure
            issues.append(
                f"tool was never executed (status '{execution.status}'"
                + (f": {failure.message}" if failure else "")
                + "); this evidence set must be empty"
            )
        for artifact in execution.artifacts:
            if artifact.truncated:
                issues.append(
                    f"artifact {artifact.id} ({artifact.kind}) exceeded the size cap and was truncated"
                )
        # Problems the parser reported: a document that did not parse, an output format
        # it did not recognise. These are not execution failures - the tool ran and
        # exited cleanly - but they mean the observations are less complete than they
        # look, which is exactly what parse_issues is for.
        issues.extend(getattr(execution, "parse_warnings", None) or [])
        return issues

    def _observation(
        self,
        evidence: Evidence,
        execution: ExecutionResult,
        *,
        action_id: Optional[str],
        artifact_ids: List[str],
        enforcer: Optional[ScopeEnforcer],
    ) -> Optional[Observation]:
        data = dict(evidence.parsed_data or {})
        subject_id = self._subject_id(data, evidence)
        observation_type = evidence.evidence_type.value

        # An observation with neither a subject nor structured data cannot be used by the World
        # Model, and inventing a subject for it would be fabrication.
        if subject_id is None and not data:
            return None

        tags = list(evidence.tags or [])
        if enforcer is not None and not any(tag in ("in_scope", "out_of_scope") for tag in tags):
            ssid = data.get("ssid")
            bssid = data.get("bssid") or data.get("mac") or data.get("ap_mac")
            ip = data.get("ip") or data.get("target_ip")
            if ssid or bssid:
                tags.append("in_scope" if enforcer.scope.is_wireless_asset_authorized(ssid, bssid) else "out_of_scope")
            elif ip:
                tags.append("in_scope" if enforcer.scope.is_ip_authorized(str(ip)) else "out_of_scope")

        stream_artifacts = [
            identifier
            for identifier in (execution.stdout_artifact, execution.stderr_artifact)
            if identifier
        ]
        interface = evidence.interface
        if not interface and execution.interface is not None:
            interface = execution.interface.name
        raw_command = evidence.source.raw_command or " ".join(execution.command)
        return Observation(
            id=evidence.id,
            type=observation_type,
            subject_id=subject_id,
            subject_type=ObservationType.subject_type_for(observation_type),
            timestamp=format_timestamp(evidence.timestamp),
            data=data,
            confidence=float(evidence.confidence),
            provenance=Provenance(
                execution_id=execution.execution_id,
                action_id=action_id,
                assessment_id=execution.assessment_id,
                correlation_id=execution.correlation_id,
                tool=execution.tool.name if execution.tool else evidence.source.tool_name,
                capability=evidence.source.capability or execution.capability,
                interface=interface,
                raw_command=raw_command,
                derived_from=list(dict.fromkeys(stream_artifacts + artifact_ids)),
                parser=evidence.source.adapter_version,
            ),
            tags=tags,
            partial=execution.status in (ExecutionStatus.PARTIAL, ExecutionStatus.TIMEOUT),
        )

    @staticmethod
    def _subject_id(data: Dict[str, Any], evidence: Evidence) -> Optional[str]:
        for key in ("bssid", "mac", "client_mac", "ap_mac", "ip", "target_ip", "name", "domain", "hostname"):
            value = data.get(key)
            if value:
                text = str(value)
                return text.upper() if text.count(":") == 5 and len(text) == 17 else text
        if evidence.interface:
            return str(evidence.interface)
        return None

    @staticmethod
    def _mark_partial(observation: Observation) -> Observation:
        return Observation(
            id=observation.id,
            type=observation.type,
            subject_id=observation.subject_id,
            subject_type=observation.subject_type,
            timestamp=observation.timestamp,
            data=observation.data,
            confidence=observation.confidence,
            provenance=observation.provenance,
            tags=observation.tags,
            partial=True,
        )

    # ------------------------------------------------------------- verification

    def _verification_requests(
        self, evidence_set: EvidenceSet, execution: ExecutionResult
    ) -> List[VerificationRequest]:
        """
        Request verification for observations that would otherwise be over-trusted.

        Requests are deduplicated per (subject, claim): observing the same WPS-enabled access
        point ten times produces one verification cycle, not ten.
        """
        requests: List[VerificationRequest] = []
        seen: set = set()

        for observation in evidence_set.observations:
            if "out_of_scope" in observation.tags:
                # Evidence about an out-of-scope asset must not drive assessment conclusions.
                continue
            for claim_type, required, sources, description, attribute, expected in self._claims_for(observation):
                if not observation.subject_id:
                    continue
                key = (observation.subject_id, claim_type, str(attribute))
                if key in seen:
                    continue
                seen.add(key)
                verification_id = self._verification_ids.setdefault(
                    (observation.subject_id, claim_type), new_verification_id()
                )
                requests.append(
                    VerificationRequest(
                        assessment_id=evidence_set.assessment_id,
                        source_engine=EngineId.EVIDENCE.value,
                        correlation_id=evidence_set.correlation_id,
                        verification_id=verification_id,
                        subject=EntityRef(
                            type=observation.subject_type or TargetType.NONE.value,
                            id=observation.subject_id,
                        ),
                        claim=Claim(
                            type=claim_type,
                            description=description,
                            attribute=attribute,
                            expected_value=expected,
                        ),
                        supporting_evidence=[observation.id],
                        required_confidence=required,
                        verification_requirements=[
                            VerificationRequirement(
                                type="independent_source",
                                value=sources,
                                description=f"at least {sources} distinct observation sources",
                            ),
                            VerificationRequirement(
                                type="freshness",
                                value=self.max_age_seconds,
                                description=f"supporting evidence no older than {self.max_age_seconds}s",
                            ),
                            VerificationRequirement(
                                type="minimum_confidence",
                                value=required,
                                description=f"aggregated confidence must reach {required}",
                            ),
                        ],
                        max_age_seconds=self.max_age_seconds,
                        min_independent_sources=sources,
                        action_id=evidence_set.action_id,
                        execution_id=execution.execution_id,
                    )
                )
        return requests

    def _claims_for(self, observation: Observation) -> List[Tuple[str, float, int, str, Optional[str], Any]]:
        """
        Derive the claims an observation implies.

        Returns ``(claim_type, required_confidence, min_sources, description, attribute,
        expected_value)`` tuples. Only claims genuinely implied by the data are produced; an
        access-point observation with no encryption data implies nothing about encryption.
        """
        claims: List[Tuple[str, float, int, str, Optional[str], Any]] = []
        policy = VERIFICATION_POLICY.get(observation.type)
        if policy:
            if observation.type == ObservationType.WPS:
                enabled = observation.data.get("wps_enabled")
                if enabled is None:
                    return claims
                claims.append(
                    (
                        policy["claim"],
                        policy["required_confidence"],
                        policy["min_independent_sources"],
                        policy["description"],
                        "wps_enabled",
                        bool(enabled),
                    )
                )
            else:
                claims.append(
                    (
                        policy["claim"],
                        policy["required_confidence"],
                        policy["min_independent_sources"],
                        policy["description"],
                        None,
                        None,
                    )
                )

        if observation.type == ObservationType.ACCESS_POINT:
            encryption = observation.data.get("encryption")
            values = [encryption] if isinstance(encryption, str) else list(encryption or [])
            weak = [value for value in values if str(value).upper() in WEAK_ENCRYPTION]
            if weak:
                claims.append(
                    (
                        ClaimType.ENCRYPTION_STATE,
                        0.85,
                        2,
                        f"access point advertises weak encryption {sorted(set(weak))}",
                        "encryption",
                        sorted(set(str(value).upper() for value in weak)),
                    )
                )
            if observation.data.get("is_hidden"):
                claims.append(
                    (
                        ClaimType.ASSET_ATTRIBUTE,
                        0.80,
                        2,
                        "access point is broadcasting a hidden SSID",
                        "is_hidden",
                        True,
                    )
                )
        return claims

    def verification_id_for(self, subject_id: str, claim_type: str) -> Optional[str]:
        """Return the verification cycle id for a claim, if one has been opened."""
        return self._verification_ids.get((subject_id, claim_type))

    def known_verification_ids(self) -> Dict[Tuple[str, str], str]:
        return dict(self._verification_ids)
