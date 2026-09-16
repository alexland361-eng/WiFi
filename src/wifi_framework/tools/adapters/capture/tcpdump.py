"""
Adapter for tcpdump - general packet capture.
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


class TcpdumpAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        cmd = ["tcpdump"]

        if interface:
            cmd.extend(["-i", interface])

        # Count
        if parameters.get("count"):
            cmd.extend(["-c", str(parameters["count"])])

        # Filter
        if parameters.get("filter"):
            cmd.append(parameters["filter"])

        # Options
        if parameters.get("no_resolve"):
            cmd.append("-n")

        if parameters.get("verbose"):
            cmd.append("-v")

        # Read file
        if parameters.get("read_file"):
            cmd.extend(["-r", parameters["read_file"]])

        # Write file
        if parameters.get("write_file"):
            cmd.extend(["-w", parameters["write_file"]])

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output
        if exit_code != 0 and not raw_output:
            return []

        # Basic parsing - tcpdump output lines
        packets = []
        for line in combined.splitlines():
            if not line.strip():
                continue
            # Skip tcpdump header lines
            if "listening on" in line.lower() or "packets captured" in line.lower():
                continue
            packets.append({"raw_line": line})

        ev = Evidence.from_tool_output(
            tool_name="tcpdump",
            capability="packet_capture",
            evidence_type=EvidenceType.CAPTURE,
            raw_output=combined,
            parsed_data={"packets": packets[:100], "packet_count": len(packets), "interface": interface},
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=" ".join(self.build_command(interface, parameters)),
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


METADATA = ToolCapabilityMetadata(
    name="tcpdump",
    display_name="tcpdump - Packet Capture",
    category=CapabilityCategory.PACKET_CAPTURE,
    description="General packet capture and analysis utility",
    tool_binary="tcpdump",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=["root"],
    ),
    inputs=["optional_interface", "optional_filter", "optional_count", "optional_read_file"],
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
    tags=["capture", "packet"],
)

ADAPTER_CLASS = TcpdumpAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
