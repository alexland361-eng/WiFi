"""
``world-state`` contract (version 1.0).

Producer: World Model. Consumer: Decision Engine.

This is the authoritative description of the current assessment state that the Decision
Engine is allowed to see. The guarantees the World Model makes about it, from the
specification, are enforced here by construction:

* entities have stable identifiers (``id`` on every entity state);
* timestamps are explicit (``first_seen`` / ``last_seen`` / ``observed_at``);
* provenance is preserved (``evidence_ids`` plus observation provenance);
* stale information is distinguishable from current information (``stale`` flag, computed
  against ``staleness_seconds``);
* uncertainty is represented explicitly (``uncertainties``);
* observations are never silently overwritten (the World Model appends; ``revision``
  increases monotonically so a consumer can detect that state moved on).

The Decision Engine treats a received WorldState as read-only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .base import BaseContract
from .common import Provenance, to_jsonable
from .envelope import EngineId
from .validation import ValidationIssue, ValidationLevel, require_confidence, require_type


@dataclass(frozen=True)
class InterfaceState:
    """Observed state of one network interface."""

    id: str
    name: str
    type: str = "unknown"
    driver: Optional[str] = None
    chipset: Optional[str] = None
    mac: Optional[str] = None
    is_up: Optional[bool] = None
    supports_monitor: bool = False
    supports_injection: bool = False
    channel: Optional[int] = None
    frequency: Optional[int] = None
    #: Capabilities actually verified in this environment, e.g. ``monitor_mode``.
    capabilities: List[str] = field(default_factory=list)
    #: True when the capability was probed rather than assumed from driver metadata.
    probed: bool = False
    last_seen: Optional[str] = None
    stale: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return to_jsonable(
            {
                "id": self.id,
                "name": self.name,
                "type": self.type,
                "driver": self.driver,
                "chipset": self.chipset,
                "mac": self.mac,
                "is_up": self.is_up,
                "supports_monitor": self.supports_monitor,
                "supports_injection": self.supports_injection,
                "channel": self.channel,
                "frequency": self.frequency,
                "capabilities": list(self.capabilities),
                "probed": self.probed,
                "last_seen": self.last_seen,
                "stale": self.stale,
            }
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InterfaceState":
        return cls(
            id=str(data["id"]),
            name=str(data.get("name") or data["id"]),
            type=str(data.get("type") or "unknown"),
            driver=data.get("driver"),
            chipset=data.get("chipset"),
            mac=data.get("mac"),
            is_up=data.get("is_up"),
            supports_monitor=bool(data.get("supports_monitor", False)),
            supports_injection=bool(data.get("supports_injection", False)),
            channel=data.get("channel"),
            frequency=data.get("frequency"),
            capabilities=list(data.get("capabilities") or []),
            probed=bool(data.get("probed", False)),
            last_seen=data.get("last_seen"),
            stale=bool(data.get("stale", False)),
        )


@dataclass(frozen=True)
class AccessPointState:
    """One observed access point."""

    id: str
    ssid: Optional[str] = None
    channel: Optional[int] = None
    frequency: Optional[int] = None
    signal_strength: Optional[int] = None
    encryption: List[str] = field(default_factory=list)
    cipher: List[str] = field(default_factory=list)
    authentication: List[str] = field(default_factory=list)
    wps_enabled: Optional[bool] = None
    wps_locked: Optional[bool] = None
    manufacturer: Optional[str] = None
    is_hidden: bool = False
    client_ids: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    evidence_ids: List[str] = field(default_factory=list)
    #: Observation sources, used by the Verification Engine to test independence.
    evidence_tools: List[str] = field(default_factory=list)
    in_scope: Optional[bool] = None
    stale: bool = False
    #: Attributes the World Model still needs, e.g. ``["ssid", "wps_enabled"]``.
    unknown_attributes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return to_jsonable(self.__dict__)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AccessPointState":
        return cls(
            id=str(data["id"]),
            ssid=data.get("ssid"),
            channel=data.get("channel"),
            frequency=data.get("frequency"),
            signal_strength=data.get("signal_strength"),
            encryption=list(data.get("encryption") or []),
            cipher=list(data.get("cipher") or []),
            authentication=list(data.get("authentication") or []),
            wps_enabled=data.get("wps_enabled"),
            wps_locked=data.get("wps_locked"),
            manufacturer=data.get("manufacturer"),
            is_hidden=bool(data.get("is_hidden", False)),
            client_ids=list(data.get("client_ids") or []),
            first_seen=data.get("first_seen"),
            last_seen=data.get("last_seen"),
            evidence_ids=list(data.get("evidence_ids") or []),
            evidence_tools=list(data.get("evidence_tools") or []),
            in_scope=data.get("in_scope"),
            stale=bool(data.get("stale", False)),
            unknown_attributes=list(data.get("unknown_attributes") or []),
        )


@dataclass(frozen=True)
class ClientState:
    """One observed wireless client."""

    id: str
    associated_ap_id: Optional[str] = None
    probed_ssids: List[str] = field(default_factory=list)
    signal_strength: Optional[int] = None
    manufacturer: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    evidence_ids: List[str] = field(default_factory=list)
    evidence_tools: List[str] = field(default_factory=list)
    in_scope: Optional[bool] = None
    stale: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return to_jsonable(self.__dict__)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ClientState":
        return cls(
            id=str(data["id"]),
            associated_ap_id=data.get("associated_ap_id"),
            probed_ssids=list(data.get("probed_ssids") or []),
            signal_strength=data.get("signal_strength"),
            manufacturer=data.get("manufacturer"),
            first_seen=data.get("first_seen"),
            last_seen=data.get("last_seen"),
            evidence_ids=list(data.get("evidence_ids") or []),
            evidence_tools=list(data.get("evidence_tools") or []),
            in_scope=data.get("in_scope"),
            stale=bool(data.get("stale", False)),
        )


@dataclass(frozen=True)
class HostState:
    """One host reachable through the assessed network."""

    id: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    os_guess: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    services: Dict[str, Any] = field(default_factory=dict)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    evidence_ids: List[str] = field(default_factory=list)
    evidence_tools: List[str] = field(default_factory=list)
    in_scope: Optional[bool] = None
    stale: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return to_jsonable(self.__dict__)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HostState":
        return cls(
            id=str(data["id"]),
            mac=data.get("mac"),
            hostname=data.get("hostname"),
            os_guess=data.get("os_guess"),
            open_ports=list(data.get("open_ports") or []),
            services=dict(data.get("services") or {}),
            first_seen=data.get("first_seen"),
            last_seen=data.get("last_seen"),
            evidence_ids=list(data.get("evidence_ids") or []),
            evidence_tools=list(data.get("evidence_tools") or []),
            in_scope=data.get("in_scope"),
            stale=bool(data.get("stale", False)),
        )


@dataclass(frozen=True)
class NetworkState:
    """A network segment observed or authorised, with the hosts discovered inside it."""

    id: str
    cidr: Optional[str] = None
    in_scope: Optional[bool] = None
    hosts: List[HostState] = field(default_factory=list)
    last_seen: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "cidr": self.cidr,
            "in_scope": self.in_scope,
            "hosts": [host.to_dict() for host in self.hosts],
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetworkState":
        return cls(
            id=str(data["id"]),
            cidr=data.get("cidr"),
            in_scope=data.get("in_scope"),
            hosts=[HostState.from_dict(host) for host in (data.get("hosts") or [])],
            last_seen=data.get("last_seen"),
        )


@dataclass(frozen=True)
class CapabilityState:
    """
    One capability as it exists in *this* environment.

    Availability is reported together with the reason it is unavailable, because the
    specification requires an unavailable capability to be reported explicitly and preserved
    in the assessment state rather than silently skipped.
    """

    name: str
    available: bool
    reason: Optional[str] = None
    category: Optional[str] = None
    tool_binary: Optional[str] = None
    tool_version: Optional[str] = None
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    interface_required: bool = False
    interface_capabilities: List[str] = field(default_factory=list)
    privileges: List[str] = field(default_factory=list)
    invasive: bool = False
    persistent: bool = False
    requires_authorization: bool = True
    mode: Optional[str] = None
    estimated_duration_seconds: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return to_jsonable(self.__dict__)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CapabilityState":
        return cls(
            name=str(data["name"]),
            available=bool(data.get("available", False)),
            reason=data.get("reason"),
            category=data.get("category"),
            tool_binary=data.get("tool_binary"),
            tool_version=data.get("tool_version"),
            inputs=list(data.get("inputs") or []),
            outputs=list(data.get("outputs") or []),
            interface_required=bool(data.get("interface_required", False)),
            interface_capabilities=list(data.get("interface_capabilities") or []),
            privileges=list(data.get("privileges") or []),
            invasive=bool(data.get("invasive", False)),
            persistent=bool(data.get("persistent", False)),
            requires_authorization=bool(data.get("requires_authorization", True)),
            mode=data.get("mode"),
            estimated_duration_seconds=data.get("estimated_duration_seconds"),
        )


@dataclass(frozen=True)
class ObservationRef:
    """A single structured observation held by the World Model."""

    id: str
    type: str
    subject_id: Optional[str] = None
    subject_type: Optional[str] = None
    observed_at: Optional[str] = None
    confidence: float = 0.6
    data: Dict[str, Any] = field(default_factory=dict)
    provenance: Provenance = field(default_factory=Provenance)
    in_scope: Optional[bool] = None
    stale: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "subject_id": self.subject_id,
            "subject_type": self.subject_type,
            "observed_at": self.observed_at,
            "confidence": self.confidence,
            "data": to_jsonable(self.data),
            "provenance": self.provenance.to_dict(),
            "in_scope": self.in_scope,
            "stale": self.stale,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ObservationRef":
        return cls(
            id=str(data["id"]),
            type=str(data.get("type") or "generic"),
            subject_id=data.get("subject_id"),
            subject_type=data.get("subject_type"),
            observed_at=data.get("observed_at"),
            confidence=float(data.get("confidence") or 0.0),
            data=dict(data.get("data") or {}),
            provenance=Provenance.from_dict(data.get("provenance")),
            in_scope=data.get("in_scope"),
            stale=bool(data.get("stale", False)),
        )


@dataclass(frozen=True)
class HypothesisRef:
    """A finding or hypothesis in its current lifecycle state."""

    id: str
    title: str = ""
    description: str = ""
    status: str = "hypothesis"
    category: Optional[str] = None
    severity: Optional[str] = None
    confidence: float = 0.5
    subject_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    #: Distinct tools behind the supporting evidence (independence input to verification).
    evidence_tools: List[str] = field(default_factory=list)
    verification_method: Optional[str] = None
    verified_at: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return to_jsonable(self.__dict__)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HypothesisRef":
        return cls(
            id=str(data["id"]),
            title=str(data.get("title") or ""),
            description=str(data.get("description") or ""),
            status=str(data.get("status") or "hypothesis"),
            category=data.get("category"),
            severity=data.get("severity"),
            confidence=float(data.get("confidence") or 0.0),
            subject_ids=list(data.get("subject_ids") or []),
            evidence_ids=list(data.get("evidence_ids") or []),
            evidence_tools=list(data.get("evidence_tools") or []),
            verification_method=data.get("verification_method"),
            verified_at=data.get("verified_at"),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
        )


@dataclass(frozen=True)
class UncertaintyRef:
    """
    An explicitly represented information gap.

    ``id`` is stable across re-publications of the same gap, so an ActionRequest can cite the
    gap it was created to resolve (``reason.information_gaps``) and the audit trail can show
    which gaps were closed by which operations.
    """

    id: str
    type: str
    priority: int = 0
    description: str = ""
    required_capabilities: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    subject_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "priority": self.priority,
            "description": self.description,
            "required_capabilities": list(self.required_capabilities),
            "context": to_jsonable(self.context),
            "subject_ids": list(self.subject_ids),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UncertaintyRef":
        return cls(
            id=str(data["id"]),
            type=str(data.get("type") or "unknown"),
            priority=int(data.get("priority") or 0),
            description=str(data.get("description") or ""),
            required_capabilities=list(data.get("required_capabilities") or []),
            context=dict(data.get("context") or {}),
            subject_ids=list(data.get("subject_ids") or []),
        )


@dataclass(kw_only=True)
class WorldState(BaseContract):
    """The authoritative assessment state, as published by the World Model."""

    SCHEMA = "world-state"
    VERSION = "1.0"
    PRODUCER = EngineId.WORLD_MODEL.value
    REQUIRED_PAYLOAD_FIELDS = ("phase", "scope", "last_updated")

    #: Assessment phase at publication time.
    phase: str = "initializing"
    #: Monotonic counter; lets a consumer detect that state moved on between messages.
    revision: int = 0
    scope: Dict[str, Any] = field(default_factory=dict)
    objective: Dict[str, Any] = field(default_factory=dict)
    interfaces: List[InterfaceState] = field(default_factory=list)
    access_points: List[AccessPointState] = field(default_factory=list)
    clients: List[ClientState] = field(default_factory=list)
    networks: List[NetworkState] = field(default_factory=list)
    observations: List[ObservationRef] = field(default_factory=list)
    #: Evidence index: identifier plus provenance, without the raw bytes.
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    hypotheses: List[HypothesisRef] = field(default_factory=list)
    findings: List[HypothesisRef] = field(default_factory=list)
    capabilities: List[CapabilityState] = field(default_factory=list)
    uncertainties: List[UncertaintyRef] = field(default_factory=list)
    channels_observed: List[int] = field(default_factory=list)
    ssids_observed: List[str] = field(default_factory=list)
    execution_summary: List[Dict[str, Any]] = field(default_factory=list)
    #: Heuristic scores carried for the Decision Engine (experience-derived, not truth).
    planner_hints: Dict[str, Any] = field(default_factory=dict)
    #: Seconds after which an observation is considered stale.
    staleness_seconds: int = 600
    last_updated: str = ""

    @classmethod
    def _coerce_payload(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        coerced = dict(payload)
        element_factories = {
            "interfaces": InterfaceState.from_dict,
            "access_points": AccessPointState.from_dict,
            "clients": ClientState.from_dict,
            "networks": NetworkState.from_dict,
            "observations": ObservationRef.from_dict,
            "hypotheses": HypothesisRef.from_dict,
            "findings": HypothesisRef.from_dict,
            "capabilities": CapabilityState.from_dict,
            "uncertainties": UncertaintyRef.from_dict,
        }
        for key, factory in element_factories.items():
            value = coerced.get(key)
            if isinstance(value, list) and value and isinstance(value[0], dict):
                coerced[key] = [factory(item) for item in value]
        return coerced

    def extra_structural_issues(self, payload: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        issues.extend(require_type(payload, "scope", dict))
        issues.extend(require_type(payload, "revision", int))
        issues.extend(require_type(payload, "staleness_seconds", int))
        if isinstance(payload.get("staleness_seconds"), int) and payload["staleness_seconds"] <= 0:
            issues.append(
                ValidationIssue(
                    level=ValidationLevel.STRUCTURAL.value,
                    code="out_of_range",
                    message="staleness_seconds must be positive",
                    field="staleness_seconds",
                )
            )
        for name in ("observations", "hypotheses", "findings"):
            for item in payload.get(name) or []:
                confidence = getattr(item, "confidence", None)
                if confidence is not None and not 0.0 <= float(confidence) <= 1.0:
                    issues.extend(require_confidence({"confidence": confidence}, level=ValidationLevel.STRUCTURAL.value))
        return issues

    # --------------------------------------------------------------- accessors

    def available_capabilities(self) -> List[CapabilityState]:
        return [capability for capability in self.capabilities if capability.available]

    def unavailable_capabilities(self) -> Dict[str, str]:
        return {
            capability.name: (capability.reason or "unavailable")
            for capability in self.capabilities
            if not capability.available
        }

    def capability(self, name: str) -> Optional[CapabilityState]:
        for capability in self.capabilities:
            if capability.name == name:
                return capability
        return None

    def access_point(self, ap_id: str) -> Optional[AccessPointState]:
        for ap in self.access_points:
            if ap.id == ap_id:
                return ap
        return None

    def interface(self, name: str) -> Optional[InterfaceState]:
        for interface in self.interfaces:
            if interface.name == name or interface.id == name:
                return interface
        return None

    def in_scope_access_points(self) -> List[AccessPointState]:
        """Access points inside the authorised scope (``in_scope is not False``)."""
        return [ap for ap in self.access_points if ap.in_scope is not False]

    def observation(self, observation_id: str) -> Optional[ObservationRef]:
        for observation in self.observations:
            if observation.id == observation_id:
                return observation
        return None

    def evidence_tools_for(self, evidence_ids: List[str]) -> List[str]:
        """Distinct tools behind a set of evidence identifiers."""
        wanted = set(evidence_ids)
        tools = set()
        for entry in self.evidence:
            if entry.get("id") in wanted and entry.get("tool"):
                tools.add(str(entry["tool"]))
        return sorted(tools)

    def summary(self) -> Dict[str, Any]:
        """Compact summary for logging; never a substitute for the full message."""
        return {
            "revision": self.revision,
            "phase": self.phase,
            "interfaces": len(self.interfaces),
            "access_points": len(self.access_points),
            "clients": len(self.clients),
            "networks": len(self.networks),
            "observations": len(self.observations),
            "hypotheses": len(self.hypotheses),
            "findings": len(self.findings),
            "capabilities_available": len(self.available_capabilities()),
            "capabilities_unavailable": len(self.capabilities) - len(self.available_capabilities()),
            "uncertainties": len(self.uncertainties),
            "last_updated": self.last_updated,
        }
