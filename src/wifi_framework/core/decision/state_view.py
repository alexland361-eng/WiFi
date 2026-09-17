"""
Read-only projection of a ``world-state`` message for the Decision Engine.

Why this module exists
----------------------
Specification section 3 forbids the Decision Engine from accessing the World Model's internal
classes, and section 19 forbids it from knowing how another engine works. The existing
heuristics in :mod:`wifi_framework.core.planning` were written against ``AssessmentState``.
Rather than fork those heuristics (which would create two planners that disagree), this module
rebuilds the narrow surface they actually touch **from the contract message alone**.

The consequence is testable and is tested: a WorldState can be serialised to JSON, read back in
a fresh process, projected through this view, and still produce the same plan. Nothing in the
Decision Engine holds a reference to live World Model objects.

Two boundaries are worth naming:

* ``WorldStateView`` is disposable. The planner writes its computed uncertainties onto the view;
  that write never reaches the World Model, which is what "treat the received state as
  read-only" means in practice.
* Capability *metadata* is resolved through the injected registry rather than being duplicated
  into the contract. The registry is the Decision Engine's own catalogue of what may be
  requested; the contract says which of those are available **in this environment**.
  ``ContractRegistryView`` makes the WorldState authoritative for that availability, so planning
  never triggers a second, disagreeing environment probe.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from ...contracts.envelope import parse_timestamp
from ...contracts.world_state import (
    AccessPointState,
    CapabilityState,
    ClientState,
    HostState,
    HypothesisRef,
    ObservationRef,
    UncertaintyRef,
    WorldState,
)
from ..models.assessment_state import AssessmentPhase, InterfaceInfo
from ..models.evidence import Evidence, EvidenceSource, EvidenceType
from ..models.finding import Finding, FindingCategory, FindingSeverity, FindingStatus


def _phase(value: str) -> AssessmentPhase:
    try:
        return AssessmentPhase(value)
    except ValueError:
        # An unknown phase must not crash planning; the safest interpretation is that the
        # assessment is still observing.
        return AssessmentPhase.WIRELESS_OBSERVATION


def _enum(enum_type: Any, value: Optional[str], default: Any) -> Any:
    if value is None:
        return default
    try:
        return enum_type(value)
    except ValueError:
        return default


def _timestamp(value: Optional[str]) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return parse_timestamp(value)
    except Exception:
        return datetime.now(timezone.utc)


def _tags_for(observation: ObservationRef) -> List[str]:
    """
    Rebuild the model-layer tag list from the contract's projections.

    ``world-state`` deliberately carries scope and staleness as explicit typed fields rather than
    a free-form tag list, so a consumer reconstructing a model-layer ``Evidence`` must derive the
    tags from those fields. An observation that made no scope claim gets no scope tag: inventing
    one here would assert authorisation nobody granted.
    """
    tags: List[str] = []
    if observation.in_scope is True:
        tags.append("in_scope")
    elif observation.in_scope is False:
        tags.append("out_of_scope")
    if observation.stale:
        tags.append("stale")
    return tags


@dataclass
class ViewWorldModel:
    """The subset of world-model queries the planning heuristics perform."""

    access_points: Dict[str, AccessPointState] = field(default_factory=dict)
    clients: Dict[str, ClientState] = field(default_factory=dict)
    network_hosts: Dict[str, HostState] = field(default_factory=dict)
    channels_observed: Set[int] = field(default_factory=set)
    ssids_observed: Set[str] = field(default_factory=set)

    def get_unidentified_aps(self) -> List[AccessPointState]:
        return [ap for ap in self.access_points.values() if ap.unknown_attributes]

    def get_wps_enabled_aps(self) -> List[AccessPointState]:
        return [ap for ap in self.access_points.values() if ap.wps_enabled]

    def get_clients_without_ap(self) -> List[ClientState]:
        return [client for client in self.clients.values() if not client.associated_ap_id]

    def get_ap_by_ssid(self, ssid: str) -> List[AccessPointState]:
        return [ap for ap in self.access_points.values() if ap.ssid == ssid]

    def summary(self) -> Dict[str, Any]:
        return {
            "access_points_count": len(self.access_points),
            "clients_count": len(self.clients),
            "network_hosts_count": len(self.network_hosts),
            "channels_observed": sorted(self.channels_observed),
            "ssids_observed": sorted(self.ssids_observed),
            "source": "world-state projection",
        }


@dataclass
class ViewScope:
    """Scope as published in the contract, with the same authorisation questions answered."""

    authorized_ssids: List[str] = field(default_factory=list)
    authorized_bssids: List[str] = field(default_factory=list)
    authorized_channels: List[int] = field(default_factory=list)
    authorized_networks: List[str] = field(default_factory=list)
    authorized_hosts: List[str] = field(default_factory=list)
    strict_mode: bool = False
    allow_broadcast_discovery: bool = True
    description: str = ""

    def is_ssid_authorized(self, ssid: Optional[str]) -> bool:
        if not self.authorized_ssids:
            return not self.strict_mode
        if not ssid:
            return False
        import re

        for pattern in self.authorized_ssids:
            try:
                compiled = (
                    re.compile(pattern, re.IGNORECASE)
                    if any(char in pattern for char in ".*+?^$[]()|\\")
                    else re.compile(f"^{re.escape(pattern)}$", re.IGNORECASE)
                )
            except re.error:
                compiled = re.compile(f"^{re.escape(pattern)}$", re.IGNORECASE)
            if compiled.match(ssid):
                return True
        return False

    def is_bssid_authorized(self, bssid: Optional[str]) -> bool:
        if not self.authorized_bssids:
            return not self.strict_mode
        if not bssid:
            return False
        return str(bssid).upper() in {item.upper() for item in self.authorized_bssids}

    def is_channel_authorized(self, channel: int) -> bool:
        return not self.authorized_channels or channel in self.authorized_channels

    def is_ip_authorized(self, ip_str: str) -> bool:
        if not self.authorized_networks and not self.authorized_hosts:
            return not self.strict_mode
        if ip_str in self.authorized_hosts:
            return True
        import ipaddress

        try:
            address = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        for cidr in self.authorized_networks:
            try:
                if address in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def is_wireless_asset_authorized(self, ssid: Optional[str] = None, bssid: Optional[str] = None) -> bool:
        if not self.authorized_ssids and not self.authorized_bssids:
            return True
        ssid_ok = self.is_ssid_authorized(ssid) if ssid else False
        bssid_ok = self.is_bssid_authorized(bssid) if bssid else False
        if ssid and bssid:
            return ssid_ok or bssid_ok
        if ssid:
            return ssid_ok
        if bssid:
            return bssid_ok
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "authorized_ssids": list(self.authorized_ssids),
            "authorized_bssids": list(self.authorized_bssids),
            "authorized_channels": list(self.authorized_channels),
            "authorized_networks": list(self.authorized_networks),
            "authorized_hosts": list(self.authorized_hosts),
            "description": self.description,
            "allow_broadcast_discovery": self.allow_broadcast_discovery,
            "strict_mode": self.strict_mode,
        }


@dataclass
class ViewExecution:
    """One entry of the published execution summary."""

    id: str
    capability_name: str
    tool_binary: str = ""
    interface: Optional[str] = None
    success: bool = False
    status: str = "success"
    exit_code: Optional[int] = None
    duration_seconds: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    action_id: Optional[str] = None
    evidence_ids: List[str] = field(default_factory=list)
    failure_reason: Optional[str] = None


class WorldStateView:
    """
    Read-only view over a WorldState message, shaped for the planning heuristics.

    Attribute names intentionally mirror ``AssessmentState`` so the existing
    :class:`~wifi_framework.core.planning.planner.AssessmentPlanner` works unchanged.
    """

    def __init__(self, world_state: WorldState, registry: Any = None) -> None:
        self.contract = world_state
        self.registry = registry
        self.id = world_state.assessment_id
        self.phase = _phase(world_state.phase)
        self.objectives: List[str] = list((world_state.objective or {}).get("objectives") or [])
        self.created_at = _timestamp(world_state.timestamp)
        self.updated_at = _timestamp(world_state.last_updated)
        self.revision = world_state.revision

        self.interfaces: Dict[str, InterfaceInfo] = {
            item.name: self._interface_info(item) for item in world_state.interfaces
        }
        self.world_model = self._world_model(world_state)
        self.scope = self._scope(world_state)
        self.evidences: List[Evidence] = [
            self._evidence(observation) for observation in world_state.observations
        ]
        self.findings: List[Finding] = [
            self._finding(item) for item in list(world_state.hypotheses) + list(world_state.findings)
        ]
        self.execution_history: List[ViewExecution] = [
            self._execution(item) for item in world_state.execution_summary
        ]
        #: Scratch space for the planner's own output. Never written back to the World Model.
        self.uncertainties: List[Dict[str, Any]] = [item.to_dict() for item in world_state.uncertainties]
        self.published_uncertainties: List[UncertaintyRef] = list(world_state.uncertainties)
        self.extra: Dict[str, Any] = dict(world_state.planner_hints or {})
        self.tags: List[str] = []

        self.available_capabilities: Dict[str, Any] = {}
        self.unavailable_capabilities: Dict[str, str] = {}
        self._capability_states: Dict[str, CapabilityState] = {item.name: item for item in world_state.capabilities}
        self._refresh_capabilities()

    # ------------------------------------------------------------- construction

    @staticmethod
    def _interface_info(item: Any) -> InterfaceInfo:
        return InterfaceInfo(
            name=item.name,
            type=item.type,
            driver=item.driver,
            chipset=item.chipset,
            mac=item.mac,
            supports_monitor=item.supports_monitor,
            supports_injection=item.supports_injection,
            is_up=bool(item.is_up),
            channel=item.channel,
            frequency=item.frequency,
            extra={"probed": item.probed, "stale": item.stale, "last_seen": item.last_seen},
        )

    @staticmethod
    def _world_model(world_state: WorldState) -> ViewWorldModel:
        hosts: Dict[str, HostState] = {}
        for network in world_state.networks:
            for host in network.hosts:
                hosts[host.id] = host
        return ViewWorldModel(
            access_points={ap.id: ap for ap in world_state.access_points},
            clients={client.id: client for client in world_state.clients},
            network_hosts=hosts,
            channels_observed=set(world_state.channels_observed),
            ssids_observed=set(world_state.ssids_observed),
        )

    @staticmethod
    def _scope(world_state: WorldState) -> ViewScope:
        payload = dict(world_state.scope or {})
        return ViewScope(
            authorized_ssids=list(payload.get("authorized_ssids") or []),
            authorized_bssids=list(payload.get("authorized_bssids") or []),
            authorized_channels=list(payload.get("authorized_channels") or []),
            authorized_networks=list(payload.get("authorized_networks") or []),
            authorized_hosts=list(payload.get("authorized_hosts") or []),
            strict_mode=bool(payload.get("strict_mode", False)),
            allow_broadcast_discovery=bool(payload.get("allow_broadcast_discovery", True)),
            description=str(payload.get("description") or ""),
        )

    @staticmethod
    def _evidence(observation: ObservationRef) -> Evidence:
        evidence_type = _enum(EvidenceType, observation.type, EvidenceType.GENERIC)
        provenance = observation.provenance
        return Evidence(
            id=observation.id,
            timestamp=_timestamp(observation.observed_at),
            evidence_type=evidence_type,
            source=EvidenceSource(
                tool_name=provenance.tool or "unknown",
                capability=provenance.capability or "unknown",
                adapter_version=provenance.parser or "1.0",
                interface=provenance.interface,
                raw_command=provenance.raw_command,
            ),
            parsed_data=dict(observation.data),
            confidence=float(observation.confidence),
            interface=provenance.interface,
            tags=_tags_for(observation),
            execution_id=provenance.execution_id,
            action_id=provenance.action_id,
            correlation_id=provenance.correlation_id,
        )

    @staticmethod
    def _finding(item: HypothesisRef) -> Finding:
        return Finding(
            id=item.id,
            title=item.title,
            description=item.description,
            category=_enum(FindingCategory, item.category, FindingCategory.WIRELESS),
            severity=_enum(FindingSeverity, item.severity, FindingSeverity.INFO),
            status=_enum(FindingStatus, item.status, FindingStatus.HYPOTHESIS),
            confidence=float(item.confidence),
            created_at=_timestamp(item.created_at),
            updated_at=_timestamp(item.updated_at),
            evidence_ids=list(item.evidence_ids),
            affected_assets=list(item.subject_ids),
            verification_method=item.verification_method,
            verified_at=_timestamp(item.verified_at) if item.verified_at else None,
        )

    @staticmethod
    def _execution(item: Dict[str, Any]) -> ViewExecution:
        return ViewExecution(
            id=str(item.get("execution_id") or ""),
            capability_name=str(item.get("capability") or ""),
            tool_binary=str(item.get("tool_binary") or ""),
            interface=item.get("interface"),
            success=bool(item.get("success", False)),
            status=str(item.get("status") or "success"),
            exit_code=item.get("exit_code"),
            duration_seconds=float(item.get("duration_seconds") or 0.0),
            timestamp=_timestamp(item.get("timestamp")),
            action_id=item.get("action_id"),
            failure_reason=item.get("failure_reason"),
        )

    def _refresh_capabilities(self) -> None:
        """Resolve capability names from the contract into registry metadata."""
        if self.registry is None:
            self.available_capabilities = {}
            self.unavailable_capabilities = {
                name: (item.reason or "unavailable")
                for name, item in self._capability_states.items()
                if not item.available
            }
            return
        for name, item in self._capability_states.items():
            metadata = self.registry.get_metadata(name)
            if metadata is None:
                # The contract names a capability this build no longer registers. Report it
                # rather than pretending it is usable.
                self.unavailable_capabilities[name] = item.reason or "capability is not registered"
                continue
            if item.available:
                self.available_capabilities[name] = metadata
            else:
                self.unavailable_capabilities[name] = item.reason or "unavailable"

    # ------------------------------------------------------------------ queries

    def get_evidence_by_type(self, evidence_type: Any) -> List[Evidence]:
        wanted = evidence_type.value if hasattr(evidence_type, "value") else evidence_type
        return [evidence for evidence in self.evidences if evidence.evidence_type.value == wanted]

    def capability_state(self, name: str) -> Optional[CapabilityState]:
        return self._capability_states.get(name)

    def uncertainty_refs(self) -> List[UncertaintyRef]:
        return list(self.published_uncertainties)

    def summary(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.id,
            "revision": self.revision,
            "phase": self.phase.value,
            "interfaces": len(self.interfaces),
            "available_capabilities": len(self.available_capabilities),
            "unavailable_capabilities": len(self.unavailable_capabilities),
            "evidences": len(self.evidences),
            "findings": len(self.findings),
            "executions": len(self.execution_history),
            "world_model": self.world_model.summary(),
        }


class ContractRegistryView:
    """
    Registry facade whose availability answers come from the WorldState.

    Planning must not re-probe the environment: capability discovery already established what
    is usable, and a second probe can disagree with the published state (for example when a
    tool becomes unavailable mid-assessment). This facade keeps the WorldState authoritative
    while leaving metadata lookups to the real registry.
    """

    def __init__(self, registry: Any, view: WorldStateView) -> None:
        self._registry = registry
        self._view = view

    # --- availability from the contract -------------------------------------

    def check_availability(self, name: str, interface: Optional[str] = None):
        state = self._view.capability_state(name)
        if state is None:
            metadata = self._registry.get_metadata(name)
            if metadata is None:
                return False, f"capability '{name}' is not registered", {}
            return False, "capability was not present in capability discovery results", {}
        if state.available:
            return True, "reported available by capability discovery", {"source": "world-state"}
        return False, state.reason or "unavailable", {"source": "world-state"}

    def get_available_capabilities(self, interface: Optional[str] = None) -> Dict[str, Any]:
        return dict(self._view.available_capabilities)

    def get_unavailable_capabilities(self, interface: Optional[str] = None) -> Dict[str, str]:
        return dict(self._view.unavailable_capabilities)

    # --- delegated metadata lookups -----------------------------------------

    def get_metadata(self, name: str):
        return self._registry.get_metadata(name)

    def list_capabilities(self) -> List[str]:
        return self._registry.list_capabilities()

    def list_by_category(self, category: Any) -> List[Any]:
        return self._registry.list_by_category(category)

    def get_adapter_class(self, name: str):
        return self._registry.get_adapter_class(name)

    def get_adapter_instance(self, name: str):
        return self._registry.get_adapter_instance(name)
