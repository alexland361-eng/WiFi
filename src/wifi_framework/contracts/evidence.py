"""
``evidence-set`` contract (version 1.0).

Producer: Evidence Engine. Consumers: World Model and Verification Engine.

The Evidence Engine decides what observable information can legitimately be extracted from an
ExecutionResult and its artifacts. Two properties are enforced by this contract:

* **Provenance is preserved back to the originating action** — every observation carries
  ``execution_id``, ``action_id``, ``tool``, and the artifacts it was derived from. Nothing
  enters the World Model without a traceable cause.
* **Extraction problems are declared, not hidden** — ``parse_issues`` records partial parses,
  unrecognised output and malformed rows. The specification is explicit that parser errors and
  ambiguous results must not automatically become definitive findings, and an undeclared
  parsing problem is how that rule gets broken in practice.

An EvidenceSet is *not* a set of findings. Promotion from observation to hypothesis to
verified finding is the Verification Engine's decision.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .base import BaseContract
from .common import ArtifactRef, ParserRef, Provenance, TargetType, to_jsonable
from .envelope import EngineId
from .validation import (
    ValidationIssue,
    ValidationLevel,
    require_confidence,
    require_type,
)


@dataclass(frozen=True)
class Observation:
    """
    One structured observation extracted from real tool output.

    ``id`` is the World Model's stable identifier for this observation, so evidence cited by a
    VerificationResult can always be resolved back to the operation that produced it.
    """

    id: str
    type: str
    subject_id: Optional[str] = None
    subject_type: Optional[str] = None
    timestamp: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.6
    provenance: Provenance = field(default_factory=Provenance)
    #: Scope tags applied by the Evidence Engine, e.g. ``in_scope`` / ``out_of_scope``.
    tags: List[str] = field(default_factory=list)
    #: True when the underlying row/record was only partially parsed.
    partial: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "subject_id": self.subject_id,
            "subject_type": self.subject_type,
            "timestamp": self.timestamp,
            "data": to_jsonable(self.data),
            "confidence": self.confidence,
            "provenance": self.provenance.to_dict(),
            "tags": list(self.tags),
            "partial": self.partial,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Observation":
        return cls(
            id=str(data["id"]),
            type=str(data.get("type") or "generic"),
            subject_id=data.get("subject_id"),
            subject_type=data.get("subject_type"),
            timestamp=data.get("timestamp"),
            data=dict(data.get("data") or {}),
            confidence=float(data.get("confidence") if data.get("confidence") is not None else 0.6),
            provenance=Provenance.from_dict(data.get("provenance")),
            tags=list(data.get("tags") or []),
            partial=bool(data.get("partial", False)),
        )

    @property
    def in_scope(self) -> Optional[bool]:
        if "in_scope" in self.tags:
            return True
        if "out_of_scope" in self.tags:
            return False
        return None


@dataclass(kw_only=True)
class EvidenceSet(BaseContract):
    """All observations legitimately extracted from one execution."""

    SCHEMA = "evidence-set"
    VERSION = "1.0"
    PRODUCER = EngineId.EVIDENCE.value
    REQUIRED_PAYLOAD_FIELDS = ("action_id", "execution_id")

    action_id: str
    execution_id: str
    observations: List[Observation] = field(default_factory=list)
    artifacts: List[ArtifactRef] = field(default_factory=list)
    parser: Optional[ParserRef] = None

    #: Capability and tool that produced the underlying execution, for quick correlation.
    capability: Optional[str] = None
    tool: Optional[str] = None
    #: Declared extraction problems: partial parses, unrecognised output, malformed rows.
    parse_issues: List[str] = field(default_factory=list)
    #: True when the execution was ``partial`` or timed out, or when observations were dropped,
    #: so a consumer knows the set is knowingly incomplete rather than complete-and-empty.
    incomplete: bool = False

    @classmethod
    def _coerce_payload(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        coerced = dict(payload)
        observations = coerced.get("observations")
        if isinstance(observations, list) and observations and isinstance(observations[0], dict):
            coerced["observations"] = [Observation.from_dict(item) for item in observations]
        artifacts = coerced.get("artifacts")
        if isinstance(artifacts, list) and artifacts and isinstance(artifacts[0], dict):
            coerced["artifacts"] = [ArtifactRef.from_dict(item) for item in artifacts]
        if isinstance(coerced.get("parser"), dict):
            coerced["parser"] = ParserRef.from_dict(coerced["parser"])
        return coerced

    def extra_structural_issues(self, payload: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        issues.extend(require_type(payload, "observations", list))
        issues.extend(require_type(payload, "parse_issues", list))
        for observation in payload.get("observations") or []:
            data = observation.to_dict() if isinstance(observation, Observation) else dict(observation)
            issues.extend(require_confidence(data, "confidence"))
            if not data.get("id"):
                issues.append(
                    ValidationIssue(
                        level=ValidationLevel.STRUCTURAL.value,
                        code="missing_field",
                        message="every observation must have a stable id",
                        field="observations[].id",
                    )
                )
            if not (data.get("provenance") or {}).get("execution_id"):
                issues.append(
                    ValidationIssue(
                        level=ValidationLevel.STRUCTURAL.value,
                        code="missing_provenance",
                        message="every observation must record the execution that produced it",
                        field="observations[].provenance.execution_id",
                    )
                )
        return issues

    # ------------------------------------------------------------------ helpers

    def observation_ids(self) -> List[str]:
        return [observation.id for observation in self.observations]

    def subjects(self) -> List[str]:
        return sorted({observation.subject_id for observation in self.observations if observation.subject_id})

    def by_type(self, observation_type: str) -> List[Observation]:
        return [observation for observation in self.observations if observation.type == observation_type]

    def by_subject(self, subject_id: str) -> List[Observation]:
        return [observation for observation in self.observations if observation.subject_id == subject_id]

    def tools(self) -> List[str]:
        """Distinct tools behind the observations in this set."""
        return sorted({observation.provenance.tool for observation in self.observations if observation.provenance.tool})

    def is_empty(self) -> bool:
        return not self.observations

    def summary(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "execution_id": self.execution_id,
            "observations": len(self.observations),
            "subjects": len(self.subjects()),
            "types": sorted({observation.type for observation in self.observations}),
            "parse_issues": len(self.parse_issues),
            "incomplete": self.incomplete,
        }


#: Observation types the Evidence Engine may emit. Mirrors ``EvidenceType`` in the model layer
#: so that a consumer can switch on them without importing model internals.
class ObservationType:
    INTERFACE = "interface"
    ACCESS_POINT = "access_point"
    CLIENT = "client"
    SIGNAL = "signal_observation"
    CHANNEL = "channel"
    AUTHENTICATION = "authentication_observation"
    WPS = "wps_observation"
    CAPTURE = "capture"
    HANDSHAKE = "handshake"
    NETWORK_HOST = "network_host"
    NETWORK_SERVICE = "network_service"
    DNS = "dns_observation"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential_observation"
    RADIO_BLOCK = "radio_block"
    DRIVER_INFO = "driver_info"
    GENERIC = "generic"

    ALL: List[str] = [
        INTERFACE,
        ACCESS_POINT,
        CLIENT,
        SIGNAL,
        CHANNEL,
        AUTHENTICATION,
        WPS,
        CAPTURE,
        HANDSHAKE,
        NETWORK_HOST,
        NETWORK_SERVICE,
        DNS,
        VULNERABILITY,
        CREDENTIAL,
        RADIO_BLOCK,
        DRIVER_INFO,
        GENERIC,
    ]

    #: Types that describe a wireless subject, so the subject reference is a BSSID.
    WIRELESS_SUBJECT: List[str] = [ACCESS_POINT, WPS, HANDSHAKE, AUTHENTICATION, SIGNAL]

    @classmethod
    def subject_type_for(cls, observation_type: str) -> str:
        """Best-effort subject classification, used to fill ``subject_type`` consistently."""
        if observation_type in cls.WIRELESS_SUBJECT:
            return TargetType.ACCESS_POINT.value
        if observation_type == cls.CLIENT:
            return TargetType.CLIENT.value
        if observation_type == cls.INTERFACE or observation_type == cls.DRIVER_INFO:
            return TargetType.INTERFACE.value
        if observation_type in (cls.NETWORK_HOST, cls.NETWORK_SERVICE):
            return TargetType.HOST.value
        if observation_type == cls.DNS:
            return TargetType.DOMAIN.value
        return TargetType.NONE.value
