"""
Action selector - selects appropriate real capability based on current evidence,
assessment objective, hardware capabilities, authorized scope, existing evidence,
and unresolved information requirements.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..models.assessment_state import AssessmentState
from ..models.capability import ToolCapabilityMetadata
from ..execution.registry import CapabilityRegistry


#: Which capability outputs are useful for which kind of information gap.
#: Module-level so the decision layer can derive ``expected_outputs`` from the same table
#: instead of maintaining a second copy that could drift.
UNCERTAINTY_OUTPUT_MAP: Dict[str, List[str]] = {
    "interface_discovery": ["interfaces", "interface_capabilities"],
    "wireless_observation": ["access_points", "clients", "signal_observations"],
    "ap_identification": ["access_points", "signal_observations"],
    "wps_state": ["wps_observations", "access_points"],
    "client_discovery": ["clients", "access_points"],
    "network_hosts": ["network_hosts"],
    "handshake_capture": ["capture", "handshake"],
    "verification": ["access_points", "network_hosts", "signal_observations"],
    "hidden_ssid": ["access_points"],
    "capability_discovery": ["interface_capabilities", "radio_block_status"],
}


class ActionSelector:
    """
    Selects next action based on uncertainties, capabilities, scope, and experience.

    Framework must never interpret presence of tool as requirement to execute it.
    Selection is determined by state rather than existence of tool.
    """

    def __init__(self, registry: CapabilityRegistry):
        self.registry = registry

    def score_capability(
        self,
        capability: ToolCapabilityMetadata,
        uncertainty: Dict[str, Any],
        state: AssessmentState,
        interface: Optional[str] = None,
    ) -> Tuple[float, str]:
        """
        Score capability for given uncertainty.

        Returns (score, reason)
        Score higher is better.
        """
        score = 0.0
        reasons = []

        # Check if capability is available
        available, reason, _ = self.registry.check_availability(capability.name, interface)
        if not available:
            return -1.0, f"Unavailable: {reason}"

        # Does capability match required capabilities for uncertainty?
        required_caps = uncertainty.get("required_capabilities", [])
        if capability.name in required_caps:
            score += 10.0
            reasons.append("Directly addresses uncertainty (in required list)")

        # Check outputs vs uncertainty type
        uncertainty_type = uncertainty.get("type", "")
        outputs = capability.outputs

        # Mapping of uncertainty types to useful outputs
        useful_outputs = UNCERTAINTY_OUTPUT_MAP.get(uncertainty_type, [])
        for out in outputs:
            if out in useful_outputs:
                score += 5.0
                reasons.append(f"Produces useful output: {out}")

        # Relevance gate. A capability that produces none of the outputs this gap needs, and is
        # not named as able to resolve it, must not be selected at all. Running it would spend
        # time and add noise without reducing uncertainty, which is exactly the "presence of a
        # tool is not a requirement to execute it" rule the framework is built on. Returning a
        # negative score makes the capability unselectable rather than merely unattractive.
        if useful_outputs and capability.name not in required_caps:
            if not any(out in useful_outputs for out in outputs):
                return -1.0, (
                    f"cannot reduce '{uncertainty_type}' uncertainty: produces "
                    f"{list(outputs) or 'no'} outputs, none of {useful_outputs} are needed"
                )

        # Prefer non-invasive for early phases
        if not capability.operational_properties.invasive:
            score += 2.0
            reasons.append("Non-invasive")

        # Prefer passive observation early
        if state.phase.value in ["initializing", "interface_discovery", "wireless_observation"]:
            if not capability.operational_properties.invasive:
                score += 3.0

        # Check if we have executed this capability recently (avoid repetition)
        recent_executions = [
            r for r in state.execution_history[-10:] if r.capability_name == capability.name
        ]
        if recent_executions:
            # Penalize repeated execution unless uncertainty suggests it
            if len(recent_executions) >= 2:
                score -= 5.0
                reasons.append(f"Executed {len(recent_executions)} times recently")

        # Check experience if available
        # Experience with high information gain should be preferred
        if hasattr(state, "extra") and "experience_scores" in state.extra:
            exp_scores = state.extra["experience_scores"]
            if capability.name in exp_scores:
                score += exp_scores[capability.name] * 2.0
                reasons.append(f"Experience score: {exp_scores[capability.name]}")

        # Scope check - if capability requires target, ensure we have authorized target
        if "bssid" in capability.inputs or "target_bssid" in capability.inputs:
            # Need APs in scope
            authorized_aps = [
                ap
                for ap in state.world_model.access_points.values()
                if state.scope.is_wireless_asset_authorized(ap.ssid, ap.bssid)
            ]
            if not authorized_aps and state.scope.authorized_bssids:
                # We have scope restrictions but no authorized APs discovered
                score -= 3.0
                reasons.append("No authorized APs in world model yet")

        # Prefer quick operations when many uncertainties
        if capability.operational_properties.estimated_duration_seconds:
            # Shorter is better when many uncertainties
            duration = capability.operational_properties.estimated_duration_seconds
            if duration < 10:
                score += 1.0
            elif duration > 60:
                score -= 1.0

        reason_str = "; ".join(reasons) if reasons else "No specific reason"
        return score, reason_str

    def select_action(
        self, state: AssessmentState, uncertainties: List[Dict[str, Any]], interface: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Select next action.

        Returns dict with:
        - capability_name
        - interface
        - parameters
        - uncertainty addressed
        - score
        - reason
        """
        if not uncertainties:
            return None

        # Get available capabilities
        available_caps = self.registry.get_available_capabilities(interface)

        if not available_caps:
            return None

        best_action = None
        best_score = -1000.0

        # For each uncertainty in priority order
        for uncertainty in uncertainties:
            for cap_name, cap_meta in available_caps.items():
                score, reason = self.score_capability(cap_meta, uncertainty, state, interface)

                if score > best_score:
                    best_score = score
                    best_action = {
                        "capability_name": cap_name,
                        "capability_metadata": cap_meta,
                        "interface": interface,
                        "parameters": {},  # Will be generated by executor from state
                        "uncertainty": uncertainty,
                        "score": score,
                        "reason": reason,
                    }

        # If best score is negative, no good action found
        if best_score < 0:
            return None

        return best_action

    def select_interface(self, state: AssessmentState, capability: ToolCapabilityMetadata) -> Optional[str]:
        """Select appropriate interface for capability."""
        if not capability.requirements.interface_required:
            return None

        # If state has interfaces, pick best one
        if state.interfaces:
            # Prefer monitor mode capable if required
            if "monitor_mode" in capability.requirements.interface_capabilities:
                for name, info in state.interfaces.items():
                    if info.supports_monitor:
                        return name
            # Otherwise first available
            return list(state.interfaces.keys())[0]

        return None
