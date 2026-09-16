"""
Adapter for arp-scan - local network host discovery.
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


class ArpScanAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        cmd = ["arp-scan"]

        if interface:
            cmd.extend(["--interface", interface])

        target = parameters.get("target") or parameters.get("network")
        if target:
            cmd.append(target)
        else:
            # Default to localnet
            cmd.append("--localnet")

        if parameters.get("retry"):
            cmd.extend(["--retry", str(parameters["retry"])])

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output
        evidences = []

        # Parse arp-scan output
        # Example:
        # 192.168.1.1   00:11:22:33:44:55   Vendor
        # 192.168.1.2   aa:bb:cc:dd:ee:ff   Vendor

        for line in combined.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("Interface:") or line.startswith("Starting") or line.startswith("Ending") or "packets" in line.lower():
                continue

            # Match IP, MAC, Vendor
            m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]{17})\s+(.*)", line)
            if m:
                ip = m.group(1)
                mac = m.group(2).upper()
                vendor = m.group(3).strip()

                ev = Evidence.from_tool_output(
                    tool_name="arp-scan",
                    capability="network_discovery",
                    evidence_type=EvidenceType.NETWORK_HOST,
                    raw_output=combined,
                    parsed_data={
                        "ip": ip,
                        "mac": mac,
                        "vendor": vendor,
                        "manufacturer": vendor,
                        "interface": interface,
                    },
                    parameters=parameters,
                    interface=interface,
                    confidence=ConfidenceLevel.HIGH,
                    execution_id=self.execution_id,
                    raw_command=f"arp-scan --interface {interface}" if interface else "arp-scan",
                )
                evidences.append(ev)

        return evidences

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


METADATA = ToolCapabilityMetadata(
    name="arp-scan",
    display_name="arp-scan - ARP Discovery",
    category=CapabilityCategory.NETWORK_DISCOVERY,
    description="Local-network host discovery where ARP-based discovery is applicable",
    tool_binary="arp-scan",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=["root"],
    ),
    inputs=["optional_interface", "optional_target"],
    outputs=["network_hosts"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=15,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["interface_unavailable", "insufficient_privileges", "tool_not_found"],
    tags=["arp", "discovery", "local"],
)

ADAPTER_CLASS = ArpScanAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
