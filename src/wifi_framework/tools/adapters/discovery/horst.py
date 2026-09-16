"""
Adapter for horst - lightweight wireless network monitoring.
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


class HorstAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        if not interface:
            raise ValueError("Interface required for horst")
        cmd = ["horst", "-i", interface]
        if parameters.get("quiet"):
            cmd.append("-q")
        if parameters.get("channel"):
            cmd.extend(["-c", str(parameters["channel"])])
        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output
        ev = Evidence.from_tool_output(
            tool_name="horst",
            capability="wireless_observation",
            evidence_type=EvidenceType.GENERIC,
            raw_output=combined,
            parsed_data={"interface": interface, "output": combined[:2000]},
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.LOW,
            execution_id=self.execution_id,
            raw_command=f"horst -i {interface}" if interface else "horst",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


METADATA = ToolCapabilityMetadata(
    name="horst",
    display_name="horst - Lightweight Wireless Monitor",
    category=CapabilityCategory.WIRELESS_OBSERVATION,
    description="Lightweight wireless network monitoring and observation utility",
    tool_binary="horst",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=True,
        interface_capabilities=["monitor_mode"],
        privileges=["root"],
    ),
    inputs=["interface", "optional_channel"],
    outputs=["access_points", "clients"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.PASSIVE_OBSERVATION,
        persistent=True,
        estimated_duration_seconds=20,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["interface_unavailable", "insufficient_privileges"],
    tags=["monitor", "lightweight"],
)

ADAPTER_CLASS = HorstAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
