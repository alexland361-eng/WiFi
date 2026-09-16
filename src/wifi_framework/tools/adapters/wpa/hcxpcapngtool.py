"""
Adapter for hcxpcapngtool - converts captured wireless auth material.
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


class HcxpcapngtoolAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        input_file = parameters.get("input_file") or parameters.get("pcapng_file")
        if not input_file:
            raise ValueError("input_file required for hcxpcapngtool")

        cmd = ["hcxpcapngtool", "-o", parameters.get("output_file", "/tmp/hash.hc22000")]

        # Input
        cmd.append(input_file)

        # Additional options
        if parameters.get("essid"):
            cmd.extend(["--essid", parameters["essid"]])

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed = {
            "input_file": parameters.get("input_file"),
            "output_file": parameters.get("output_file", "/tmp/hash.hc22000"),
            "success": exit_code == 0,
        }

        # Parse counts
        import re

        m = re.search(r"(\d+)\s+PMKID.*written", combined, re.IGNORECASE)
        if m:
            parsed["pmkid_count"] = int(m.group(1))

        m = re.search(r"(\d+)\s+EAPOL.*written", combined, re.IGNORECASE)
        if m:
            parsed["eapol_count"] = int(m.group(1))

        m = re.search(r"(\d+)\s+handshake", combined, re.IGNORECASE)
        if m:
            parsed["handshake_count"] = int(m.group(1))

        ev = Evidence.from_tool_output(
            tool_name="hcxpcapngtool",
            capability="wpa_conversion",
            evidence_type=EvidenceType.HANDSHAKE,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.HIGH if exit_code == 0 else ConfidenceLevel.LOW,
            execution_id=self.execution_id,
            raw_command=f"hcxpcapngtool -o {parsed['output_file']} {parsed['input_file']}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("input_file") and not parameters.get("pcapng_file"):
            return False, ["input_file required"]
        return True, []


METADATA = ToolCapabilityMetadata(
    name="hcxpcapngtool",
    display_name="hcxpcapngtool - Capture Conversion",
    category=CapabilityCategory.WPA_ASSESSMENT,
    description="Converts and processes captured wireless authentication material into formats suitable for analysis",
    tool_binary="hcxpcapngtool",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["input_file", "optional_output_file", "optional_essid"],
    outputs=["handshake", "credential_observation"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.OFFLINE_ANALYSIS,
        persistent=False,
        estimated_duration_seconds=10,
        produces_pcap=False,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found", "invalid_parameters"],
    tags=["wpa", "conversion", "hash"],
)

ADAPTER_CLASS = HcxpcapngtoolAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
