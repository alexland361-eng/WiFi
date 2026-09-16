"""
Adapter for dumpcap - Wireshark's capture engine.
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


class DumpcapAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        cmd = ["dumpcap"]

        if interface:
            cmd.extend(["-i", interface])

        if parameters.get("count"):
            cmd.extend(["-c", str(parameters["count"])])

        if parameters.get("write_file"):
            cmd.extend(["-w", parameters["write_file"]])

        if parameters.get("duration"):
            cmd.extend(["-a", f"duration:{parameters['duration']}"])

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output
        ev = Evidence.from_tool_output(
            tool_name="dumpcap",
            capability="packet_capture",
            evidence_type=EvidenceType.CAPTURE,
            raw_output=combined,
            parsed_data={"interface": interface, "output": combined[:2000]},
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"dumpcap -i {interface}" if interface else "dumpcap",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


METADATA = ToolCapabilityMetadata(
    name="dumpcap",
    display_name="dumpcap - Wireshark Capture Engine",
    category=CapabilityCategory.PACKET_CAPTURE,
    description="Wireshark's capture engine for packet acquisition",
    tool_binary="dumpcap",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=["root"],
    ),
    inputs=["optional_interface", "optional_write_file", "optional_count"],
    outputs=["capture"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.PASSIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=15,
        produces_pcap=True,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["interface_unavailable", "insufficient_privileges"],
    tags=["capture", "wireshark"],
)

ADAPTER_CLASS = DumpcapAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
