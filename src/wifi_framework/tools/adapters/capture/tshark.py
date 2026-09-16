"""
Adapter for tshark - command-line Wireshark engine.
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
from ....core.models.evidence import Evidence
from ....parsers.tshark import tshark_to_evidences


class TsharkAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        cmd = ["tshark"]

        if interface:
            cmd.extend(["-i", interface])

        # Capture filter
        if parameters.get("capture_filter"):
            cmd.extend(["-f", parameters["capture_filter"]])

        # Display filter
        if parameters.get("display_filter"):
            cmd.extend(["-Y", parameters["display_filter"]])

        # Read from file
        if parameters.get("read_file"):
            cmd.extend(["-r", parameters["read_file"]])

        # Output format
        output_format = parameters.get("output_format", "fields")
        if output_format == "json":
            cmd.extend(["-T", "json"])
        elif output_format == "fields":
            cmd.extend(["-T", "fields"])
            fields = parameters.get("fields", ["frame.number", "wlan.sa", "wlan.da", "wlan_mgt.ssid"])
            for f in fields:
                cmd.extend(["-e", f])
        else:
            cmd.extend(["-T", output_format])

        # Count
        if parameters.get("count"):
            cmd.extend(["-c", str(parameters["count"])])

        # Duration
        if parameters.get("duration"):
            cmd.extend(["-a", f"duration:{parameters['duration']}"])

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output if raw_output else error_output
        if exit_code != 0 and not combined.strip():
            return []

        return tshark_to_evidences(combined, interface=interface, execution_id=self.execution_id)

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


METADATA = ToolCapabilityMetadata(
    name="tshark",
    display_name="tshark - CLI Wireshark Engine",
    category=CapabilityCategory.PACKET_CAPTURE,
    description="Command-line Wireshark engine suitable for automated parsing",
    tool_binary="tshark",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=["root"],
    ),
    inputs=["optional_interface", "optional_capture_filter", "optional_display_filter", "optional_read_file"],
    outputs=["capture", "access_points", "clients"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.PASSIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=15,
        produces_pcap=True,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["interface_unavailable", "insufficient_privileges", "invalid_parameters"],
    tags=["capture", "wireshark", "analysis"],
)

ADAPTER_CLASS = TsharkAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
