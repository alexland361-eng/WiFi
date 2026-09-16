"""
Adapter for hcxdumptool - wireless capture and authentication-material collection.
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


class HcxdumptoolAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        if not interface:
            raise ValueError("Interface required for hcxdumptool")

        cmd = ["hcxdumptool", "-i", interface]

        # Output file
        if parameters.get("output_file"):
            cmd.extend(["-o", parameters["output_file"]])
        else:
            cmd.extend(["-o", "/tmp/hcxdumptool.pcapng"])

        # Channel
        if parameters.get("channel"):
            cmd.extend(["-c", str(parameters["channel"])])

        # Enable status
        cmd.append("--enable_status=1")

        # Additional options
        if parameters.get("filterlist"):
            cmd.extend(["--filterlist", parameters["filterlist"]])

        if parameters.get("filtermode"):
            cmd.extend(["--filtermode", str(parameters["filtermode"])])

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed = {
            "interface": interface,
            "output_file": parameters.get("output_file", "/tmp/hcxdumptool.pcapng"),
            "captured": exit_code == 0,
        }

        # Parse status info if present
        # hcxdumptool outputs counters
        if "PMKID" in combined:
            parsed["pmkid_captured"] = True
        if "EAPOL" in combined:
            parsed["eapol_captured"] = True

        ev = Evidence.from_tool_output(
            tool_name="hcxdumptool",
            capability="wpa_capture",
            evidence_type=EvidenceType.CAPTURE,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.HIGH if exit_code == 0 else ConfidenceLevel.LOW,
            execution_id=self.execution_id,
            raw_command=f"hcxdumptool -i {interface}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


METADATA = ToolCapabilityMetadata(
    name="hcxdumptool",
    display_name="hcxdumptool - WPA Capture",
    category=CapabilityCategory.WPA_ASSESSMENT,
    description="Wireless capture and authentication-material collection utility for authorized assessment",
    tool_binary="hcxdumptool",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=True,
        interface_capabilities=["monitor_mode"],
        privileges=["root"],
    ),
    inputs=["interface", "optional_output_file", "optional_channel"],
    outputs=["capture", "handshake", "authentication_observations"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=True,
        estimated_duration_seconds=60,
        produces_pcap=True,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=[
        "interface_unavailable",
        "unsupported_driver",
        "insufficient_privileges",
        "timeout",
    ],
    tags=["wpa", "capture", "pmkid"],
)

ADAPTER_CLASS = HcxdumptoolAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
