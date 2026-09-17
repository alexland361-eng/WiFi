"""
Adapter for `iwconfig` - legacy wireless interface configuration.
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


class IwconfigAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        if interface:
            return ["iwconfig", interface]
        return ["iwconfig"]

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        if exit_code != 0 and not raw_output:
            return []

        evidences = []
        # Parse iwconfig output
        # Example:
        # wlan0     IEEE 802.11  ESSID:"MyNetwork"
        #           Mode:Managed  Frequency:2.437 GHz  Access Point: 00:11:22:33:44:55
        #           ...

        current_iface = None
        current_data: Dict[str, Any] = {}

        for line in (raw_output + "\n" + error_output).splitlines():
            if not line.strip():
                if current_iface and current_data:
                    ev = Evidence.from_tool_output(
                        tool_name="iwconfig",
                        capability="wireless_interface_discovery",
                        evidence_type=EvidenceType.INTERFACE,
                        raw_output=raw_output,
                        parsed_data={"name": current_iface, **current_data},
                        parameters=parameters,
                        interface=current_iface,
                        confidence=ConfidenceLevel.MEDIUM,
                        execution_id=self.execution_id,
                        raw_command=f"iwconfig {current_iface}" if current_iface else "iwconfig",
                    )
                    evidences.append(ev)
                    current_data = {}
                    current_iface = None
                continue

            # New interface line starts without leading spaces
            if not line.startswith(" ") and not line.startswith("\t"):
                # Save previous
                if current_iface and current_data:
                    ev = Evidence.from_tool_output(
                        tool_name="iwconfig",
                        capability="wireless_interface_discovery",
                        evidence_type=EvidenceType.INTERFACE,
                        raw_output=raw_output,
                        parsed_data={"name": current_iface, **current_data},
                        parameters=parameters,
                        interface=current_iface,
                        confidence=ConfidenceLevel.MEDIUM,
                        execution_id=self.execution_id,
                        raw_command=f"iwconfig {current_iface}",
                    )
                    evidences.append(ev)

                # Parse new interface
                parts = line.split()
                if parts:
                    current_iface = parts[0]
                    current_data = {}

                    # Check for no wireless extensions
                    if "no wireless extensions" in line.lower():
                        current_data["wireless"] = False
                        continue
                    else:
                        current_data["wireless"] = True

                    # Parse ESSID
                    m = re.search(r'ESSID:"([^"]*)"', line)
                    if m:
                        current_data["ssid"] = m.group(1)

                    # Mode
                    m = re.search(r"Mode:(\w+)", line)
                    if m:
                        current_data["type"] = m.group(1).lower()

                    # Access Point
                    m = re.search(r"Access Point:\s+([0-9A-Fa-f:]{17})", line)
                    if m:
                        current_data["ap_mac"] = m.group(1).upper()

            else:
                # Continuation line
                if not current_iface:
                    continue

                m = re.search(r"Frequency:([\d\.]+)\s*GHz", line)
                if m:
                    try:
                        current_data["frequency"] = int(float(m.group(1)) * 1000)
                    except ValueError:
                        pass

                m = re.search(r"Channel:(\d+)", line)
                if m:
                    try:
                        current_data["channel"] = int(m.group(1))
                    except ValueError:
                        pass

        # Final
        if current_iface and current_data:
            ev = Evidence.from_tool_output(
                tool_name="iwconfig",
                capability="wireless_interface_discovery",
                evidence_type=EvidenceType.INTERFACE,
                raw_output=raw_output,
                parsed_data={"name": current_iface, **current_data},
                parameters=parameters,
                interface=current_iface,
                confidence=ConfidenceLevel.MEDIUM,
                execution_id=self.execution_id,
                raw_command=f"iwconfig {current_iface}" if current_iface else "iwconfig",
            )
            evidences.append(ev)

        return evidences

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


METADATA = ToolCapabilityMetadata(
    name="iwconfig",
    display_name="iwconfig - Legacy Wireless Interface Info",
    category=CapabilityCategory.WIRELESS_INTERFACE,
    description="Legacy wireless interface configuration and inspection utility",
    tool_binary="iwconfig",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["optional_interface"],
    outputs=["interfaces", "signal_observations"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.PASSIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=2,
        invasive=False,
        requires_authorization=False,
    ),
    failure_conditions=["interface_unavailable", "tool_not_found"],
    tags=["interface", "legacy"],
)


ADAPTER_CLASS = IwconfigAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
