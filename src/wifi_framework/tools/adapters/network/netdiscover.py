"""
Adapter for netdiscover - network discovery.
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


class NetdiscoverAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        cmd = ["netdiscover"]

        if interface:
            cmd.extend(["-i", interface])

        if parameters.get("range"):
            cmd.extend(["-r", parameters["range"]])
        elif parameters.get("target"):
            cmd.extend(["-r", parameters["target"]])

        # Passive mode
        if parameters.get("passive"):
            cmd.append("-p")

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output
        evidences = []

        # Parse netdiscover output
        # Example:
        # 192.168.1.1  00:11:22:33:44:55  1  60  Router
        for line in combined.splitlines():
            line = line.strip()
            if not line:
                continue
            if "Currently scanning" in line or "Screen View" in line or "---" in line:
                continue

            m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]{17})\s+.*", line)
            if m:
                ip = m.group(1)
                mac = m.group(2).upper()

                ev = Evidence.from_tool_output(
                    tool_name="netdiscover",
                    capability="network_discovery",
                    evidence_type=EvidenceType.NETWORK_HOST,
                    raw_output=combined,
                    parsed_data={
                        "ip": ip,
                        "mac": mac,
                        "interface": interface,
                    },
                    parameters=parameters,
                    interface=interface,
                    confidence=ConfidenceLevel.MEDIUM,
                    execution_id=self.execution_id,
                    raw_command=f"netdiscover -i {interface}" if interface else "netdiscover",
                )
                evidences.append(ev)

        return evidences

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


METADATA = ToolCapabilityMetadata(
    name="netdiscover",
    display_name="netdiscover - Network Discovery",
    category=CapabilityCategory.NETWORK_DISCOVERY,
    description="Network discovery functionality, particularly useful during local-network reconnaissance",
    tool_binary="netdiscover",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=["root"],
    ),
    inputs=["optional_interface", "optional_range", "optional_passive"],
    outputs=["network_hosts"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=20,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["interface_unavailable", "insufficient_privileges"],
    tags=["discovery", "arp"],
)

ADAPTER_CLASS = NetdiscoverAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
