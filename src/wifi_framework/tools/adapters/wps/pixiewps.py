"""
Adapter for pixiewps - specialized WPS protocol analysis.
"""
from __future__ import annotations

import re
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


class PixiewpsAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        # pixiewps typically works with reaver or bully output, or pcap
        # It can also take parameters like -e, -r, -s, etc.
        cmd = ["pixiewps"]

        # Common parameters
        if parameters.get("pke"):
            cmd.extend(["--pke", parameters["pke"]])
        if parameters.get("pkr"):
            cmd.extend(["--pkr", parameters["pkr"]])
        if parameters.get("e_nonce"):
            cmd.extend(["--e-nonce", parameters["e_nonce"]])
        if parameters.get("r_nonce"):
            cmd.extend(["--r-nonce", parameters["r_nonce"]])
        if parameters.get("e_hash1"):
            cmd.extend(["--e-hash1", parameters["e_hash1"]])
        if parameters.get("e_hash2"):
            cmd.extend(["--e-hash2", parameters["e_hash2"]])
        if parameters.get("authkey"):
            cmd.extend(["--authkey", parameters["authkey"]])

        # If no specific params, show help/version for availability check
        if len(cmd) == 1:
            cmd.append("--help")

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed = {
            "interface": interface,
        }

        # Look for WPS pin
        pin_match = re.search(r"WPS pin:\s*(\d+)", combined, re.IGNORECASE)
        if pin_match:
            parsed["wps_pin"] = pin_match.group(1)

        # Check for success
        if "WPS pin" in combined and pin_match:
            parsed["success"] = True
        else:
            parsed["success"] = False

        ev = Evidence.from_tool_output(
            tool_name="pixiewps",
            capability="wps_assessment",
            evidence_type=EvidenceType.WPS,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.HIGH if parsed.get("wps_pin") else ConfidenceLevel.LOW,
            execution_id=self.execution_id,
            raw_command="pixiewps",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


METADATA = ToolCapabilityMetadata(
    name="pixiewps",
    display_name="pixiewps - WPS Protocol Analysis",
    category=CapabilityCategory.WPS_ASSESSMENT,
    description="Specialized WPS protocol analysis/testing utility used alongside WPS assessment workflows",
    tool_binary="pixiewps",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=[
        "optional_pke",
        "optional_pkr",
        "optional_e_nonce",
        "optional_r_nonce",
        "optional_e_hash1",
        "optional_e_hash2",
        "optional_authkey",
    ],
    outputs=["wps_observations", "credential_observation"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.OFFLINE_ANALYSIS,
        persistent=False,
        estimated_duration_seconds=10,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found", "invalid_parameters"],
    tags=["wps", "pixie", "offline"],
)

ADAPTER_CLASS = PixiewpsAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
