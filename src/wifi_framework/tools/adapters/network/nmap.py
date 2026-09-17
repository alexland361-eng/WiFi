"""
Adapter for nmap - host discovery, service enumeration.
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
from ....parsers.nmap import nmap_to_evidences


class NmapAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        target = parameters.get("target") or parameters.get("target_ip") or parameters.get("ip")
        if not target:
            raise ValueError("Target required for nmap")

        cmd = ["nmap"]

        # Scan type
        scan_type = parameters.get("scan_type", "-sV")  # default version detection
        if scan_type:
            cmd.append(scan_type)

        # Ports
        if parameters.get("ports"):
            cmd.extend(["-p", parameters["ports"]])

        # Output format - we want grepable for parsing
        if parameters.get("output_format") == "xml":
            cmd.extend(["-oX", "-"])
        elif parameters.get("output_format") == "grepable":
            cmd.extend(["-oG", "-"])
        else:
            # Default to normal, but also grepable via -oG -
            # We'll use -oG - for easy parsing, and also normal to stdout
            # Actually nmap can output both, but we choose grepable for parser
            # However parser also handles normal
            if not parameters.get("no_grepable"):
                cmd.extend(["-oG", "-"])

        # Timing
        if parameters.get("timing"):
            cmd.append(parameters["timing"])

        # Additional args
        if parameters.get("additional_args"):
            cmd.extend(parameters["additional_args"].split())

        cmd.append(target)

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output
        if exit_code != 0 and not combined.strip():
            return []

        target = parameters.get("target") or parameters.get("target_ip") or parameters.get("ip")
        issues: List[str] = []
        evidences = nmap_to_evidences(
            combined, target=target, execution_id=self.execution_id, issues=issues
        )
        self.parse_warnings.extend(issues)
        return evidences

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        target = parameters.get("target") or parameters.get("target_ip") or parameters.get("ip")
        if not target:
            return False, ["Target required"]
        return True, []


METADATA = ToolCapabilityMetadata(
    name="nmap",
    display_name="nmap - Network Discovery",
    category=CapabilityCategory.NETWORK_DISCOVERY,
    description="Host discovery, service enumeration, version detection, and network-security assessment within authorized scope",
    tool_binary="nmap",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["target", "optional_scan_type", "optional_ports", "optional_timing"],
    outputs=["network_hosts", "network_services"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=60,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["invalid_parameters", "tool_not_found", "timeout"],
    tags=["network", "discovery", "enumeration"],
)

ADAPTER_CLASS = NmapAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
