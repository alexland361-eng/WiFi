"""
Uncertainty identification - determines what information is currently known,
identifies important uncertainties.

The framework continuously maintains internal model, determines what is known,
identifies uncertainties, evaluates which action can provide useful additional evidence.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..models.assessment_state import AssessmentState, AssessmentPhase
from ..models.evidence import EvidenceType


class UncertaintyIdentifier:
    """
    Identifies uncertainties in current assessment state.

    Uncertainties drive adaptive action selection.
    """

    def identify(self, state: AssessmentState) -> List[Dict[str, Any]]:
        """
        Identify current uncertainties.

        Returns list of uncertainty dicts with:
        - type: what is unknown
        - priority: how important
        - description
        - required_capabilities: what tools could help
        - context: relevant data
        """
        uncertainties = []

        # Phase-based uncertainties
        if state.phase == AssessmentPhase.INITIALIZING:
            uncertainties.append(
                {
                    "type": "interface_discovery",
                    "priority": 10,
                    "description": "Wireless interfaces not yet discovered",
                    "required_capabilities": ["iw_dev", "iwconfig", "airmon-ng"],
                    "context": {},
                }
            )

        if not state.interfaces:
            uncertainties.append(
                {
                    "type": "interface_discovery",
                    "priority": 10,
                    "description": "No wireless interfaces discovered",
                    "required_capabilities": ["iw_dev", "iwconfig", "iw_list"],
                    "context": {},
                }
            )

        if not state.available_capabilities:
            uncertainties.append(
                {
                    "type": "capability_discovery",
                    "priority": 9,
                    "description": "Tool capabilities not yet discovered",
                    "required_capabilities": ["iw_list", "rfkill"],
                    "context": {},
                }
            )

        # Wireless observation uncertainties
        if len(state.world_model.access_points) == 0:
            uncertainties.append(
                {
                    "type": "wireless_observation",
                    "priority": 8,
                    "description": "No access points observed yet",
                    "required_capabilities": ["airodump-ng", "kismet", "tshark"],
                    "context": {"channels_observed": list(state.world_model.channels_observed)},
                }
            )
        else:
            # Check for APs with incomplete info
            incomplete_aps = state.world_model.get_unidentified_aps()
            if incomplete_aps:
                uncertainties.append(
                    {
                        "type": "ap_identification",
                        "priority": 7,
                        "description": f"{len(incomplete_aps)} access points with incomplete information",
                        "required_capabilities": ["airodump-ng", "tshark"],
                        "context": {"bssids": [ap.bssid for ap in incomplete_aps[:5]]},
                    }
                )

            # Check for hidden SSIDs
            hidden_aps = [ap for ap in state.world_model.access_points.values() if ap.is_hidden]
            if hidden_aps:
                uncertainties.append(
                    {
                        "type": "hidden_ssid",
                        "priority": 6,
                        "description": f"{len(hidden_aps)} hidden SSIDs observed",
                        "required_capabilities": ["airodump-ng", "tshark"],
                        "context": {"bssids": [ap.bssid for ap in hidden_aps]},
                    }
                )

            # WPS state unknown for many APs
            wps_unknown = [ap for ap in state.world_model.access_points.values() if ap.wps_enabled is None]
            if wps_unknown and len(wps_unknown) > len(state.world_model.access_points) * 0.5:
                uncertainties.append(
                    {
                        "type": "wps_state",
                        "priority": 5,
                        "description": f"WPS state unknown for {len(wps_unknown)} access points",
                        "required_capabilities": ["wash", "airodump-ng"],
                        "context": {"bssids": [ap.bssid for ap in wps_unknown[:5]]},
                    }
                )

        # Client uncertainties
        if len(state.world_model.access_points) > 0 and len(state.world_model.clients) == 0:
            uncertainties.append(
                {
                    "type": "client_discovery",
                    "priority": 6,
                    "description": "No wireless clients observed despite APs found",
                    "required_capabilities": ["airodump-ng", "tshark"],
                    "context": {},
                }
            )

        # Network discovery uncertainties (if we have network access)
        if state.phase in [AssessmentPhase.NETWORK_DISCOVERY, AssessmentPhase.SERVICE_ENUMERATION]:
            if len(state.world_model.network_hosts) == 0:
                uncertainties.append(
                    {
                        "type": "network_hosts",
                        "priority": 7,
                        "description": "No network hosts discovered",
                        "required_capabilities": ["nmap", "arp-scan", "netdiscover", "fping"],
                        "context": {},
                    }
                )

        # Authentication material uncertainties
        handshake_evidences = state.get_evidence_by_type(EvidenceType.HANDSHAKE)
        capture_evidences = state.get_evidence_by_type(EvidenceType.CAPTURE)
        if state.world_model.access_points and not handshake_evidences and not capture_evidences:
            # If we have WPA2 APs, we might want to capture handshakes
            wpa_aps = [
                ap
                for ap in state.world_model.access_points.values()
                if any("WPA" in enc for enc in ap.encryption)
            ]
            if wpa_aps:
                uncertainties.append(
                    {
                        "type": "handshake_capture",
                        "priority": 5,
                        "description": f"{len(wpa_aps)} WPA-enabled APs but no handshake captured",
                        "required_capabilities": ["hcxdumptool", "airodump-ng"],
                        "context": {"bssids": [ap.bssid for ap in wpa_aps[:3]]},
                    }
                )

        # Verification uncertainties
        # Findings that are hypotheses but not yet verified
        from ..models.finding import FindingStatus

        unverified = [f for f in state.findings if f.status == FindingStatus.HYPOTHESIS]
        if unverified:
            uncertainties.append(
                {
                    "type": "verification",
                    "priority": 4,
                    "description": f"{len(unverified)} findings need verification",
                    "required_capabilities": ["tshark", "nmap", "airodump-ng"],
                    "context": {"finding_ids": [f.id for f in unverified[:3]]},
                }
            )

        # Sort by priority descending
        uncertainties.sort(key=lambda x: x["priority"], reverse=True)

        return uncertainties
