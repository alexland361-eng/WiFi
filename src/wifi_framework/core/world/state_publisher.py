"""
World Model -> ``world-state`` publisher.

This module is the only place that turns live assessment state into the contract the Decision
Engine is allowed to consume. It exists to make the boundary real: the Decision Engine receives
a serialised message, not a reference to mutable model objects.

Guarantees implemented here (specification section 3):

* **stable identifiers** - entities keep their natural key (BSSID, MAC, IP, interface name);
  uncertainties get a deterministic ``gap-<digest>`` id derived from their type and subjects, so
  the same gap keeps the same id across re-publications and an ActionRequest can cite it.
* **explicit timestamps** - ``first_seen`` / ``last_seen`` / ``observed_at`` are always emitted.
* **provenance preserved** - every observation carries execution, action, tool and artifact ids.
* **staleness distinguishable** - ``stale`` is computed against ``staleness_seconds``.
* **uncertainty explicit** - published as ``uncertainties`` with priority and subjects.
* **observations never silently overwritten** - the underlying store is append-only; ``revision``
  increases with every publication so a consumer can tell that state moved on.
"""
from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set

from ...contracts.common import Provenance
from ...contracts.envelope import EngineId, format_timestamp, utc_now
from ...contracts.world_state import (
    AccessPointState,
    CapabilityState,
    ClientState,
    HostState,
    HypothesisRef,
    InterfaceState,
    NetworkState,
    ObservationRef,
    UncertaintyRef,
    WorldState,
)
from ..models.assessment_state import AssessmentState
from ..models.evidence import Evidence
from ..models.finding import Finding, FindingStatus

#: Finding statuses that are still open questions rather than conclusions.
OPEN_STATUSES: Set[str] = {
    FindingStatus.HYPOTHESIS.value,
    FindingStatus.SUPPORTED.value,
    FindingStatus.UNRESOLVED.value,
    FindingStatus.REFUTED.value,
}
#: Finding statuses the World Model treats as conclusions.
CLOSED_STATUSES: Set[str] = {FindingStatus.VERIFIED.value, FindingStatus.CONFIRMED.value}

#: Attributes of an access point that matter for assessment decisions.
_AP_ATTRIBUTES = ("ssid", "channel", "encryption", "wps_enabled")

#: Default freshness window. Wireless observations age quickly: an AP seen ten minutes ago may
#: have changed channel, and a client may have roamed. The value is configurable per assessment.
DEFAULT_STALENESS_SECONDS = 600


def uncertainty_id(uncertainty_type: str, subject_ids: Iterable[str]) -> str:
    """
    Deterministic identifier for an information gap.

    Derived only from the gap's type and the entities it concerns - never from counters or
    phrasing - so the id is stable while the gap persists and changes when the gap changes.
    """
    subjects = ",".join(sorted({str(subject) for subject in subject_ids if subject}))
    digest = hashlib.sha1(f"{uncertainty_type}|{subjects}".encode("utf-8")).hexdigest()
    return f"gap-{digest[:12]}"


def _iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return format_timestamp(value)


def _is_stale(value: Optional[datetime], now: datetime, staleness_seconds: int) -> bool:
    if value is None:
        return False
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return (now - value).total_seconds() > staleness_seconds


class WorldStatePublisher:
    """Publishes ``world-state`` messages from the authoritative assessment state."""

    def __init__(self, staleness_seconds: int = DEFAULT_STALENESS_SECONDS) -> None:
        if staleness_seconds <= 0:
            raise ValueError(f"staleness_seconds must be positive, got {staleness_seconds}")
        self.staleness_seconds = staleness_seconds
        self._revision = 0

    @property
    def revision(self) -> int:
        """Revision of the most recently published message."""
        return self._revision

    # ------------------------------------------------------------------ public

    def publish(self, state: AssessmentState, *, correlation_id: Optional[str] = None) -> WorldState:
        """Build the ``world-state`` message describing ``state`` right now."""
        self._revision += 1
        now = utc_now()
        tool_index = self._tool_index(state.evidences)

        world = WorldState(
            assessment_id=state.id,
            source_engine=EngineId.WORLD_MODEL.value,
            correlation_id=correlation_id or state.id,
            phase=state.phase.value,
            revision=self._revision,
            scope=state.scope.to_dict(),
            objective={
                "description": state.scope.description,
                "objectives": list(state.objectives),
                "strict_mode": state.scope.strict_mode,
                "allow_broadcast_discovery": state.scope.allow_broadcast_discovery,
            },
            interfaces=self._interfaces(state, now),
            access_points=self._access_points(state, now, tool_index),
            clients=self._clients(state, now, tool_index),
            networks=self._networks(state, now, tool_index),
            observations=self._observations(state, now),
            evidence=self._evidence_index(state),
            hypotheses=self._hypotheses(state, tool_index, OPEN_STATUSES),
            findings=self._hypotheses(state, tool_index, CLOSED_STATUSES),
            capabilities=self._capabilities(state),
            uncertainties=self._uncertainties(state),
            channels_observed=sorted(state.world_model.channels_observed),
            ssids_observed=sorted(state.world_model.ssids_observed),
            execution_summary=self._execution_summary(state),
            planner_hints=self._planner_hints(state),
            staleness_seconds=self.staleness_seconds,
            last_updated=_iso(state.updated_at) or format_timestamp(now),
        )
        return world

    # --------------------------------------------------------------- projections

    @staticmethod
    def _tool_index(evidences: List[Evidence]) -> Dict[str, str]:
        return {evidence.id: evidence.source.tool_name for evidence in evidences}

    @staticmethod
    def _tools_for(evidence_ids: List[str], tool_index: Dict[str, str]) -> List[str]:
        return sorted({tool_index[eid] for eid in evidence_ids if eid in tool_index and tool_index[eid]})

    def _interfaces(self, state: AssessmentState, now: datetime) -> List[InterfaceState]:
        result: List[InterfaceState] = []
        for name, info in state.interfaces.items():
            extra = dict(getattr(info, "extra", {}) or {})
            capabilities: List[str] = []
            if info.supports_monitor:
                capabilities.append("monitor_mode")
            if info.supports_injection:
                capabilities.append("packet_injection")
            if info.is_up:
                capabilities.append("up")
            result.append(
                InterfaceState(
                    id=name,
                    name=name,
                    type=info.type or "unknown",
                    driver=info.driver,
                    chipset=info.chipset,
                    mac=info.mac,
                    is_up=bool(info.is_up),
                    supports_monitor=bool(info.supports_monitor),
                    supports_injection=bool(info.supports_injection),
                    channel=info.channel,
                    frequency=info.frequency,
                    capabilities=capabilities,
                    # ``probed`` distinguishes a verified capability from driver metadata that
                    # merely claims it - the distinction the Execution Engine replans on.
                    probed=bool(extra.get("monitor_tested") or extra.get("injection_tested")),
                    last_seen=_iso(state.updated_at),
                    stale=False,
                )
            )
        return result

    def _access_points(
        self, state: AssessmentState, now: datetime, tool_index: Dict[str, str]
    ) -> List[AccessPointState]:
        result: List[AccessPointState] = []
        for bssid, ap in state.world_model.access_points.items():
            unknown = [
                attribute
                for attribute in _AP_ATTRIBUTES
                if getattr(ap, attribute, None) in (None, "", [])
            ]
            result.append(
                AccessPointState(
                    id=bssid,
                    ssid=ap.ssid,
                    channel=ap.channel,
                    frequency=ap.frequency,
                    signal_strength=ap.signal_strength,
                    encryption=list(ap.encryption),
                    cipher=list(ap.cipher),
                    authentication=list(ap.authentication),
                    wps_enabled=ap.wps_enabled,
                    wps_locked=ap.wps_locked,
                    manufacturer=ap.manufacturer,
                    is_hidden=bool(ap.is_hidden),
                    client_ids=sorted(ap.client_macs),
                    first_seen=_iso(ap.first_seen),
                    last_seen=_iso(ap.last_seen),
                    evidence_ids=list(ap.evidence_ids),
                    evidence_tools=self._tools_for(ap.evidence_ids, tool_index),
                    in_scope=state.scope.is_wireless_asset_authorized(ap.ssid, bssid),
                    stale=_is_stale(ap.last_seen, now, self.staleness_seconds),
                    unknown_attributes=unknown,
                )
            )
        result.sort(key=lambda item: item.id)
        return result

    def _clients(
        self, state: AssessmentState, now: datetime, tool_index: Dict[str, str]
    ) -> List[ClientState]:
        result: List[ClientState] = []
        for mac, client in state.world_model.clients.items():
            in_scope: Optional[bool] = None
            if client.associated_bssid:
                ap = state.world_model.access_points.get(client.associated_bssid)
                in_scope = state.scope.is_wireless_asset_authorized(
                    ap.ssid if ap else None, client.associated_bssid
                )
            result.append(
                ClientState(
                    id=mac,
                    associated_ap_id=client.associated_bssid,
                    probed_ssids=list(client.ssid_probed),
                    signal_strength=client.signal_strength,
                    manufacturer=client.manufacturer,
                    first_seen=_iso(client.first_seen),
                    last_seen=_iso(client.last_seen),
                    evidence_ids=list(client.evidence_ids),
                    evidence_tools=self._tools_for(client.evidence_ids, tool_index),
                    in_scope=in_scope,
                    stale=_is_stale(client.last_seen, now, self.staleness_seconds),
                )
            )
        result.sort(key=lambda item: item.id)
        return result

    def _networks(
        self, state: AssessmentState, now: datetime, tool_index: Dict[str, str]
    ) -> List[NetworkState]:
        """Group observed hosts under the authorised networks they belong to."""
        hosts: Dict[str, HostState] = {}
        for ip, host in state.world_model.network_hosts.items():
            hosts[ip] = HostState(
                id=ip,
                mac=host.mac,
                hostname=host.hostname,
                os_guess=host.os_guess,
                open_ports=list(host.open_ports),
                services={str(port): info for port, info in (host.services or {}).items()},
                first_seen=_iso(host.first_seen),
                last_seen=_iso(host.last_seen),
                evidence_ids=list(host.evidence_ids),
                evidence_tools=self._tools_for(host.evidence_ids, tool_index),
                in_scope=state.scope.is_ip_authorized(ip),
                stale=_is_stale(host.last_seen, now, self.staleness_seconds),
            )

        networks: List[NetworkState] = []
        assigned: Set[str] = set()
        for cidr in state.scope.authorized_networks:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            members = [
                host
                for ip, host in hosts.items()
                if self._in_network(ip, network)
            ]
            assigned.update(host.id for host in members)
            networks.append(
                NetworkState(
                    id=str(network),
                    cidr=str(network),
                    in_scope=True,
                    hosts=sorted(members, key=lambda item: item.id),
                    last_seen=_iso(now),
                )
            )

        # Hosts observed outside every authorised network are still reported: the framework
        # must distinguish in-scope assets from unrelated ones rather than hide them.
        unassigned = [host for ip, host in hosts.items() if ip not in assigned]
        if unassigned:
            networks.append(
                NetworkState(
                    id="observed-unscoped",
                    cidr=None,
                    in_scope=False,
                    hosts=sorted(unassigned, key=lambda item: item.id),
                    last_seen=_iso(now),
                )
            )
        return networks

    @staticmethod
    def _in_network(ip: str, network: Any) -> bool:
        try:
            return ipaddress.ip_address(ip) in network
        except ValueError:
            return False

    def _observations(self, state: AssessmentState, now: datetime) -> List[ObservationRef]:
        result: List[ObservationRef] = []
        for evidence in state.evidences:
            data = dict(evidence.parsed_data or {})
            subject_id = (
                data.get("bssid")
                or data.get("mac")
                or data.get("client_mac")
                or data.get("ip")
                or data.get("target_ip")
                or data.get("name")
            )
            result.append(
                ObservationRef(
                    id=evidence.id,
                    type=evidence.evidence_type.value,
                    subject_id=str(subject_id).upper() if subject_id and isinstance(subject_id, str) and ":" in subject_id else (str(subject_id) if subject_id else None),
                    subject_type=self._subject_type(evidence),
                    observed_at=_iso(evidence.timestamp),
                    confidence=float(evidence.confidence),
                    data=data,
                    provenance=Provenance(
                        execution_id=evidence.execution_id,
                        action_id=evidence.action_id,
                        assessment_id=state.id,
                        correlation_id=evidence.correlation_id,
                        tool=evidence.source.tool_name,
                        capability=evidence.source.capability,
                        interface=evidence.interface,
                        raw_command=evidence.source.raw_command,
                        parser=evidence.source.adapter_version,
                    ),
                    # Scope is a claim, not an inference: only an explicit scope tag states it.
                    # An evidence record tagged only with, say, "wps_locked" has made no scope
                    # assertion, and projecting ``in_scope=True`` for it would invent one.
                    in_scope=(
                        True
                        if "in_scope" in evidence.tags
                        else False
                        if "out_of_scope" in evidence.tags
                        else None
                    ),
                    stale=_is_stale(evidence.timestamp, now, self.staleness_seconds),
                )
            )
        return result

    @staticmethod
    def _subject_type(evidence: Evidence) -> Optional[str]:
        from ...contracts.evidence import ObservationType

        return ObservationType.subject_type_for(evidence.evidence_type.value)

    def _evidence_index(self, state: AssessmentState) -> List[Dict[str, Any]]:
        """Lightweight evidence index: identity and provenance, without the payload."""
        index: List[Dict[str, Any]] = []
        for evidence in state.evidences:
            index.append(
                {
                    "id": evidence.id,
                    "type": evidence.evidence_type.value,
                    "timestamp": _iso(evidence.timestamp),
                    "confidence": float(evidence.confidence),
                    "tool": evidence.source.tool_name,
                    "capability": evidence.source.capability,
                    "execution_id": evidence.execution_id,
                    "action_id": evidence.action_id,
                    "correlation_id": evidence.correlation_id,
                    "interface": evidence.interface,
                    "tags": list(evidence.tags),
                }
            )
        return index

    def _hypotheses(
        self, state: AssessmentState, tool_index: Dict[str, str], statuses: Set[str]
    ) -> List[HypothesisRef]:
        result: List[HypothesisRef] = []
        for finding in state.findings:
            if finding.status.value not in statuses:
                continue
            result.append(self._hypothesis_ref(finding, tool_index))
        result.sort(key=lambda item: item.id)
        return result

    @staticmethod
    def _hypothesis_ref(finding: Finding, tool_index: Dict[str, str]) -> HypothesisRef:
        return HypothesisRef(
            id=finding.id,
            title=finding.title,
            description=finding.description,
            status=finding.status.value,
            category=finding.category.value,
            severity=finding.severity.value,
            confidence=float(finding.confidence),
            subject_ids=list(finding.affected_assets),
            evidence_ids=list(finding.evidence_ids),
            evidence_tools=sorted(
                {tool_index[eid] for eid in finding.evidence_ids if eid in tool_index and tool_index[eid]}
            ),
            verification_method=finding.verification_method,
            verified_at=_iso(finding.verified_at),
            created_at=_iso(finding.created_at),
            updated_at=_iso(finding.updated_at),
        )

    def _capabilities(self, state: AssessmentState) -> List[CapabilityState]:
        result: List[CapabilityState] = []
        for name, metadata in state.available_capabilities.items():
            result.append(self._capability_state(metadata, available=True, reason=None))
        for name, reason in state.unavailable_capabilities.items():
            if name in state.available_capabilities:
                continue
            result.append(
                CapabilityState(
                    name=name,
                    available=False,
                    # The reason is preserved, not discarded: an unavailable capability is a
                    # fact about the environment that the Decision Engine must be able to see.
                    reason=str(reason),
                )
            )
        result.sort(key=lambda item: item.name)
        return result

    @staticmethod
    def _capability_state(metadata: Any, *, available: bool, reason: Optional[str]) -> CapabilityState:
        requirements = metadata.requirements
        properties = metadata.operational_properties
        return CapabilityState(
            name=metadata.name,
            available=available,
            reason=reason,
            category=metadata.category.value if hasattr(metadata.category, "value") else str(metadata.category),
            tool_binary=metadata.tool_binary,
            tool_version=metadata.version,
            inputs=list(metadata.inputs),
            outputs=list(metadata.outputs),
            interface_required=bool(requirements.interface_required),
            interface_capabilities=list(requirements.interface_capabilities),
            privileges=list(requirements.privileges),
            invasive=bool(properties.invasive),
            persistent=bool(properties.persistent),
            requires_authorization=bool(properties.requires_authorization),
            mode=properties.mode.value if hasattr(properties.mode, "value") else str(properties.mode),
            estimated_duration_seconds=properties.estimated_duration_seconds,
        )

    def _uncertainties(self, state: AssessmentState) -> List[UncertaintyRef]:
        result: List[UncertaintyRef] = []
        for uncertainty in state.uncertainties or []:
            context = dict(uncertainty.get("context") or {})
            subjects: List[str] = []
            for key in ("bssids", "finding_ids", "ips", "interfaces", "macs"):
                value = context.get(key)
                if isinstance(value, list):
                    subjects.extend(str(item) for item in value)
            utype = str(uncertainty.get("type") or "unknown")
            result.append(
                UncertaintyRef(
                    id=uncertainty_id(utype, subjects),
                    type=utype,
                    priority=int(uncertainty.get("priority") or 0),
                    description=str(uncertainty.get("description") or ""),
                    required_capabilities=[str(item) for item in (uncertainty.get("required_capabilities") or [])],
                    context=context,
                    subject_ids=sorted(set(subjects)),
                )
            )
        # Highest priority first, matching the order the Decision Engine should consider them.
        result.sort(key=lambda item: (-item.priority, item.type, item.id))
        return result

    @staticmethod
    def _execution_summary(state: AssessmentState) -> List[Dict[str, Any]]:
        summary: List[Dict[str, Any]] = []
        for record in state.execution_history:
            summary.append(
                {
                    "execution_id": record.id,
                    "action_id": record.action_id,
                    "correlation_id": record.correlation_id,
                    "capability": record.capability_name,
                    "tool_binary": record.tool_binary,
                    "interface": record.interface,
                    "status": record.status or ("success" if record.success else "failed"),
                    "success": bool(record.success),
                    "exit_code": record.exit_code,
                    "duration_seconds": record.duration_seconds,
                    "timestamp": _iso(record.timestamp),
                    "evidence_count": len(record.evidence_ids),
                    "failure_reason": record.failure_reason,
                }
            )
        return summary

    @staticmethod
    def _planner_hints(state: AssessmentState) -> Dict[str, Any]:
        """
        Heuristic priors the Decision Engine may use.

        Kept separate from factual state: experience scores are a ranking hint, never a claim
        about the environment, and must not be mistaken for observations.
        """
        extra = state.extra or {}
        return {
            "experience_scores": dict(extra.get("experience_scores") or {}),
            "phase_transitions": list(extra.get("phase_transitions") or []),
            "blocked_capabilities": dict(extra.get("blocked_capabilities") or {}),
        }
