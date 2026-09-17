"""
Adapter for Kismet - passive wireless reconnaissance platform.

Kismet is treated as long-running observation source rather than one-shot scanner.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ....core.execution.adapter_base import ToolAdapterBase
from ....core.models.capability import (
    CapabilityCategory,
    CapabilityRequirements,
    OperationalMode,
    OperationalProperties,
    OperatingSystem,
    ToolCapabilityMetadata,
)
from ....core.models.evidence import ConfidenceLevel, Evidence, EvidenceType


class KismetAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        # Kismet can be run in different modes
        # For simplicity, we support kismet --version check and basic capture
        # Real Kismet usage often requires config file and server mode

        mode = parameters.get("mode", "version")  # version, server, capture

        if mode == "version":
            return ["kismet", "--version"]
        elif mode == "server":
            cmd = ["kismet", "--no-ncurses-wrapper"]
            if interface:
                cmd.extend(["-c", f"{interface}:type=linuxwifi"])
            # Use temp dir for logs
            log_prefix = parameters.get("log_prefix", "/tmp/kismet")
            cmd.extend(["--log-prefix", log_prefix])
            return cmd
        else:
            # Default to help to check availability
            return ["kismet", "--help"]

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output
        evidences = []

        mode = parameters.get("mode", "version")

        if mode == "version":
            # Parse version info
            ev = Evidence.from_tool_output(
                tool_name="kismet",
                capability="wireless_observation",
                evidence_type=EvidenceType.GENERIC,
                raw_output=combined,
                parsed_data={"version_info": combined[:500], "mode": mode},
                parameters=parameters,
                interface=interface,
                confidence=ConfidenceLevel.MEDIUM,
                execution_id=self.execution_id,
                raw_command="kismet --version",
            )
            evidences.append(ev)
        else:
            # Try to parse Kismet logs or output
            # For long-running, we'd parse its REST API or log files
            # Here we provide basic evidence
            ev = Evidence.from_tool_output(
                tool_name="kismet",
                capability="wireless_observation",
                evidence_type=EvidenceType.GENERIC,
                raw_output=combined,
                parsed_data={"mode": mode, "note": "Kismet long-running capture, check logs"},
                parameters=parameters,
                interface=interface,
                confidence=ConfidenceLevel.LOW,
                execution_id=self.execution_id,
                raw_command=" ".join(self.build_command(interface, parameters)),
            )
            evidences.append(ev)

        return evidences

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


METADATA = ToolCapabilityMetadata(
    name="kismet",
    display_name="Kismet - Passive Wireless Reconnaissance",
    category=CapabilityCategory.WIRELESS_OBSERVATION,
    description="Major passive wireless reconnaissance platform capable of maintaining continuously updated view of wireless devices",
    tool_binary="kismet",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        interface_capabilities=["monitor_mode"],
        privileges=["root"],
    ),
    inputs=["optional_interface", "optional_mode", "optional_log_prefix"],
    outputs=["access_points", "clients", "signal_observations"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.PASSIVE_OBSERVATION,
        persistent=True,
        estimated_duration_seconds=60,
        produces_pcap=True,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=[
        "interface_unavailable",
        "insufficient_privileges",
        "tool_not_found",
        "timeout",
    ],
    tags=["passive", "recon", "kismet"],
)

ADAPTER_CLASS = KismetAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
