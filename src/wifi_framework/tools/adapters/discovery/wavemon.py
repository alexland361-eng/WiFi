"""
Adapter for wavemon - wireless interface and signal information.
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


class WavemonAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        cmd = ["wavemon"]
        if interface:
            cmd.extend(["-i", interface])
        # Wavemon is interactive, we use -d for dump or just check availability
        if parameters.get("dump"):
            cmd.append("-d")
        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output
        ev = Evidence.from_tool_output(
            tool_name="wavemon",
            capability="wireless_observation",
            evidence_type=EvidenceType.SIGNAL,
            raw_output=combined,
            parsed_data={"interface": interface, "signal_info": combined[:2000]},
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.LOW,
            execution_id=self.execution_id,
            raw_command=f"wavemon -i {interface}" if interface else "wavemon",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


METADATA = ToolCapabilityMetadata(
    name="wavemon",
    display_name="wavemon - Signal Monitor",
    category=CapabilityCategory.WIRELESS_OBSERVATION,
    description="Provides wireless interface and signal information useful for diagnostics",
    tool_binary="wavemon",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["optional_interface"],
    outputs=["signal_observations"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.PASSIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=5,
        invasive=False,
        requires_authorization=False,
    ),
    failure_conditions=["interface_unavailable", "tool_not_found"],
    tags=["signal", "diagnostics"],
)

ADAPTER_CLASS = WavemonAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
