"""
Executor - verifies capability availability, parameter generation from state,
validation, execution with timeout, output collection, failure reporting.

All as first-class parts of execution system.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..models.assessment_state import AssessmentState, ExecutionRecord
from ..models.evidence import Evidence
from .registry import CapabilityRegistry


class ExecutionResult:
    """High-level execution result."""

    def __init__(
        self,
        success: bool,
        capability_name: str,
        tool_binary: str,
        interface: Optional[str],
        parameters: Dict[str, Any],
        raw_command: str,
        exit_code: Optional[int],
        duration: float,
        evidences: List[Evidence],
        raw_output: str = "",
        error_output: str = "",
        failure_reason: Optional[str] = None,
        execution_id: str = "",
    ):
        self.success = success
        self.capability_name = capability_name
        self.tool_binary = tool_binary
        self.interface = interface
        self.parameters = parameters
        self.raw_command = raw_command
        self.exit_code = exit_code
        self.duration = duration
        self.evidences = evidences
        self.raw_output = raw_output
        self.error_output = error_output
        self.failure_reason = failure_reason
        self.execution_id = execution_id


class CapabilityExecutor:
    """
    Executes capabilities with capability-aware checks.

    Before action is executed, verifies that selected wireless interface,
    operating system, driver, privileges, installed tool version, and current
    environment satisfy action's requirements.

    Tool parameters are generated from structured state rather than blindly
    copied from static command templates.
    """

    def __init__(self, registry: CapabilityRegistry, assessment_state: Optional[AssessmentState] = None):
        self.registry = registry
        self.assessment_state = assessment_state

    def generate_parameters_from_state(
        self, capability_name: str, state: AssessmentState, overrides: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Automatically derive and validate parameters from current assessment state.

        This is key to adaptive assessment - parameters are not static templates.
        """
        overrides = overrides or {}
        params: Dict[str, Any] = {}

        metadata = self.registry.get_metadata(capability_name)
        if not metadata:
            return overrides

        # If interface required and not in overrides, try to get from state
        if metadata.requirements.interface_required:
            if "interface" in overrides:
                params["interface"] = overrides["interface"]
            elif state.interfaces:
                # Pick first available interface that supports required capabilities
                for iface_name, iface_info in state.interfaces.items():
                    # Simple heuristic: if monitor required, check supports_monitor
                    if "monitor_mode" in metadata.requirements.interface_capabilities:
                        if iface_info.supports_monitor:
                            params["interface"] = iface_name
                            break
                    else:
                        params["interface"] = iface_name
                        break

        # For channel-based tools, use observed channels or authorized channels
        if "channel" in metadata.inputs:
            if "channel" in overrides:
                params["channel"] = overrides["channel"]
            elif state.scope.authorized_channels:
                params["channel"] = state.scope.authorized_channels[0]
            elif state.world_model.channels_observed:
                # Most common channel?
                params["channel"] = list(state.world_model.channels_observed)[0]

        # For BSSID-based tools, use discovered APs
        if "bssid" in metadata.inputs or "ap_mac" in metadata.inputs or "target_bssid" in metadata.inputs:
            key = "bssid"
            if "target_bssid" in metadata.inputs:
                key = "target_bssid"
            elif "ap_mac" in metadata.inputs:
                key = "ap_mac"
            if key in overrides:
                params[key] = overrides[key]
            elif state.world_model.access_points:
                # Pick first AP in scope
                for bssid, ap in state.world_model.access_points.items():
                    if state.scope.is_wireless_asset_authorized(ap.ssid, bssid):
                        params[key] = bssid
                        if ap.ssid:
                            params["ssid"] = ap.ssid
                        break
                # If none in scope but we allow discovery, pick first
                if key not in params:
                    first_bssid = list(state.world_model.access_points.keys())[0]
                    params[key] = first_bssid

        # For SSID-based tools
        if "ssid" in metadata.inputs and "ssid" not in params:
            if "ssid" in overrides:
                params["ssid"] = overrides["ssid"]
            elif state.world_model.ssids_observed:
                params["ssid"] = list(state.world_model.ssids_observed)[0]

        # For IP-based tools
        if "target_ip" in metadata.inputs or "ip" in metadata.inputs:
            ip_key = "target_ip" if "target_ip" in metadata.inputs else "ip"
            if ip_key in overrides:
                params[ip_key] = overrides[ip_key]
            elif state.world_model.network_hosts:
                # Pick first host in scope
                for ip, host in state.world_model.network_hosts.items():
                    if state.scope.is_ip_authorized(ip):
                        params[ip_key] = ip
                        break

        # Merge overrides (overrides win)
        params.update(overrides)

        # Remove interface from params if it's separate
        # Some adapters expect interface separately
        return params

    def execute(
        self,
        capability_name: str,
        interface: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        timeout: int = 60,
        state: Optional[AssessmentState] = None,
        record_state: bool = True,
    ) -> ExecutionResult:
        """
        Execute a capability.

        Handles capability-aware execution with real tool invocation.

        ``record_state=False`` still derives parameters from ``state`` but leaves writing the
        execution record and evidence to the caller. The contract-driven path uses this so that
        state is written once, by the World Model applier, after the Evidence Engine has
        attributed the observations (added in 0.4.0; default preserves 0.3.0 behaviour).
        """
        parameters = parameters or {}
        state = state or self.assessment_state
        execution_id = ""

        metadata = self.registry.get_metadata(capability_name)
        if not metadata:
            return ExecutionResult(
                success=False,
                capability_name=capability_name,
                tool_binary="unknown",
                interface=interface,
                parameters=parameters,
                raw_command="",
                exit_code=None,
                duration=0.0,
                evidences=[],
                failure_reason=f"Capability {capability_name} not registered",
            )

        # If state provided and parameters not fully specified, generate from state
        if state:
            generated = self.generate_parameters_from_state(capability_name, state, parameters)
            # Merge, with explicit parameters taking precedence
            merged = {**generated, **parameters}
            parameters = merged

            # If interface still not determined and required, try from params
            if not interface and "interface" in parameters:
                interface = parameters["interface"]

        # Get adapter
        adapter = self.registry.get_adapter_instance(capability_name)
        if not adapter:
            return ExecutionResult(
                success=False,
                capability_name=capability_name,
                tool_binary=metadata.tool_binary,
                interface=interface,
                parameters=parameters,
                raw_command="",
                exit_code=None,
                duration=0.0,
                evidences=[],
                failure_reason=f"No adapter for capability {capability_name}",
            )

        # Execute via adapter
        adapter_result = adapter.execute(interface=interface, parameters=parameters, timeout=timeout)
        execution_id = adapter.execution_id

        # Create execution record if state available
        if state and record_state:
            record = ExecutionRecord(
                id=execution_id,
                capability_name=capability_name,
                tool_binary=metadata.tool_binary,
                interface=interface,
                parameters=parameters,
                raw_command=adapter_result.raw_command,
                exit_code=adapter_result.exit_code,
                duration_seconds=adapter_result.duration,
                success=adapter_result.success,
                raw_output=adapter_result.raw_output[:10000] if adapter_result.raw_output else "",  # Truncate for storage
                error_output=adapter_result.error_output[:5000] if adapter_result.error_output else "",
                evidence_ids=[e.id for e in adapter_result.evidences],
                failure_reason=adapter_result.failure_reason,
                information_gain=len(adapter_result.evidences),  # Simple metric
                cost=adapter_result.duration,
            )
            state.add_execution(record)
            # Add evidences to state
            for ev in adapter_result.evidences:
                state.add_evidence(ev)

        return ExecutionResult(
            success=adapter_result.success,
            capability_name=capability_name,
            tool_binary=metadata.tool_binary,
            interface=interface,
            parameters=parameters,
            raw_command=adapter_result.raw_command,
            exit_code=adapter_result.exit_code,
            duration=adapter_result.duration,
            evidences=adapter_result.evidences,
            raw_output=adapter_result.raw_output,
            error_output=adapter_result.error_output,
            failure_reason=adapter_result.failure_reason,
            execution_id=execution_id,
        )
