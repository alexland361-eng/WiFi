"""
Planner - deterministic execution and evidence layers remain functional independently,
while AI and learning components act as additional decision-making capabilities.

Operates as iterative observation-and-decision loop:
Observe → Model → Identify uncertainty → Select action → Parameterize → Execute → Parse → Verify → Update → Re-evaluate
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from ..models.assessment_state import AssessmentState, AssessmentPhase
from ..execution.registry import CapabilityRegistry
from .action_selector import ActionSelector
from .uncertainty import UncertaintyIdentifier


class AssessmentPlanner:
    """
    Adaptive assessment planner.

    The assessment process is state-driven rather than tool-driven.
    """

    def __init__(self, registry: CapabilityRegistry):
        self.registry = registry
        self.uncertainty_identifier = UncertaintyIdentifier()
        self.action_selector = ActionSelector(registry)

    def plan_next_action(
        self, state: AssessmentState, interface: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Plan next action based on current state.

        Returns action dict or None if assessment should complete.
        """
        # Identify uncertainties
        uncertainties = self.uncertainty_identifier.identify(state)
        state.uncertainties = uncertainties

        if not uncertainties:
            # No uncertainties, assessment may be complete
            return None

        # Select interface if not provided
        if not interface:
            # Try to find best interface from state
            if state.interfaces:
                # Prefer first interface that is up
                for name, info in state.interfaces.items():
                    if info.is_up:
                        interface = name
                        break
                if not interface:
                    interface = list(state.interfaces.keys())[0]

        # Select action
        action = self.action_selector.select_action(state, uncertainties, interface)

        return action

    def should_continue(self, state: AssessmentState, max_iterations: int = 100) -> bool:
        """Determine if assessment should continue."""
        # Check iteration limit
        if len(state.execution_history) >= max_iterations:
            return False

        # Check phase
        if state.phase in [AssessmentPhase.COMPLETED, AssessmentPhase.FAILED]:
            return False

        # If no uncertainties, complete
        uncertainties = self.uncertainty_identifier.identify(state)
        if not uncertainties:
            return False

        # If only low priority uncertainties left, maybe complete
        high_priority = [u for u in uncertainties if u["priority"] >= 5]
        if not high_priority:
            # Only low priority left, could continue or complete based on objectives
            if len(state.execution_history) > 20:  # Arbitrary threshold
                return False

        return True

    def suggest_phase_transition(self, state: AssessmentState) -> Optional[AssessmentPhase]:
        """Suggest next phase based on current state."""
        # Simple heuristic for phase transitions
        if state.phase == AssessmentPhase.INITIALIZING:
            if state.interfaces:
                return AssessmentPhase.INTERFACE_DISCOVERY
            else:
                return AssessmentPhase.INTERFACE_DISCOVERY

        if state.phase == AssessmentPhase.INTERFACE_DISCOVERY:
            if state.available_capabilities:
                return AssessmentPhase.CAPABILITY_DISCOVERY
            else:
                return AssessmentPhase.CAPABILITY_DISCOVERY

        if state.phase == AssessmentPhase.CAPABILITY_DISCOVERY:
            return AssessmentPhase.WIRELESS_OBSERVATION

        if state.phase == AssessmentPhase.WIRELESS_OBSERVATION:
            if len(state.world_model.access_points) > 0:
                # Check if WPS assessment needed
                wps_aps = state.world_model.get_wps_enabled_aps()
                if wps_aps:
                    return AssessmentPhase.WPS_ASSESSMENT
                return AssessmentPhase.ASSET_IDENTIFICATION
            else:
                # Still need wireless observation
                return None

        if state.phase == AssessmentPhase.WPS_ASSESSMENT:
            return AssessmentPhase.AUTHENTICATION_ASSESSMENT

        if state.phase == AssessmentPhase.AUTHENTICATION_ASSESSMENT:
            # If we have network hosts, go to network discovery
            if state.world_model.network_hosts:
                return AssessmentPhase.NETWORK_DISCOVERY
            return AssessmentPhase.ASSET_IDENTIFICATION

        if state.phase == AssessmentPhase.ASSET_IDENTIFICATION:
            if state.world_model.network_hosts:
                return AssessmentPhase.NETWORK_DISCOVERY
            return AssessmentPhase.VERIFICATION

        if state.phase == AssessmentPhase.NETWORK_DISCOVERY:
            if state.world_model.network_hosts:
                return AssessmentPhase.SERVICE_ENUMERATION
            return AssessmentPhase.VERIFICATION

        if state.phase == AssessmentPhase.SERVICE_ENUMERATION:
            return AssessmentPhase.VULNERABILITY_ASSESSMENT

        if state.phase == AssessmentPhase.VULNERABILITY_ASSESSMENT:
            return AssessmentPhase.VERIFICATION

        if state.phase == AssessmentPhase.VERIFICATION:
            return AssessmentPhase.REPORTING

        if state.phase == AssessmentPhase.REPORTING:
            return AssessmentPhase.COMPLETED

        return None
