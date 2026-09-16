"""
Adapter for `airmon-ng` - interface and monitor-mode management.
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


class AirmonNgAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        action = parameters.get("action", "check")  # check, start, stop
        if action == "start":
            if not interface:
                raise ValueError("Interface required for airmon-ng start")
            cmd = ["airmon-ng", "start", interface]
            channel = parameters.get("channel")
            if channel:
                cmd.append(str(channel))
            return cmd
        elif action == "stop":
            if not interface:
                raise ValueError("Interface required for airmon-ng stop")
            return ["airmon-ng", "stop", interface]
        elif action == "check":
            return ["airmon-ng", "check"]
        else:
            # Default: list interfaces
            return ["airmon-ng"]

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        if exit_code != 0 and not raw_output:
            return []

        evidences = []
        action = parameters.get("action", "check")
        combined = raw_output + "\n" + error_output

        if action == "check":
            # Parse process list that may interfere
            # airmon-ng check outputs processes
            interfering = []
            for line in combined.splitlines():
                # Look for PID lines
                m = re.search(r"^\s*(\d+)\s+(\S+)", line)
                if m:
                    try:
                        pid = int(m.group(1))
                        name = m.group(2)
                        interfering.append({"pid": pid, "name": name})
                    except ValueError:
                        pass

            ev = Evidence.from_tool_output(
                tool_name="airmon-ng",
                capability="radio_management",
                evidence_type=EvidenceType.GENERIC,
                raw_output=raw_output,
                parsed_data={"interfering_processes": interfering, "action": action},
                parameters=parameters,
                interface=interface,
                confidence=ConfidenceLevel.MEDIUM,
                execution_id=self.execution_id,
                raw_command="airmon-ng check",
            )
            evidences.append(ev)

        else:
            # Parse interface creation
            # Example: (mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)
            monitor_iface = None
            m = re.search(r"on\s+\[phy\d+\](\w+mon)", combined)
            if m:
                monitor_iface = m.group(1)
            else:
                m = re.search(r"\(monitor mode vif enabled.*?\)\s*(\w+)", combined)
                if m:
                    monitor_iface = m.group(1)

            # Also parse PHY and driver info
            interfaces = []
            # airmon-ng without args lists interfaces
            for line in combined.splitlines():
                # PHY    Interface    Driver        Chipset
                if "PHY" in line and "Interface" in line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    # Try to detect interface line
                    if re.match(r"phy\d+", parts[0]) and len(parts) >= 2:
                        phy = parts[0]
                        iface = parts[1]
                        driver = parts[2] if len(parts) > 2 else ""
                        chipset = " ".join(parts[3:]) if len(parts) > 3 else ""
                        interfaces.append(
                            {"phy": phy, "name": iface, "driver": driver, "chipset": chipset}
                        )

            parsed_data = {
                "action": action,
                "monitor_interface": monitor_iface,
                "interfaces": interfaces,
                "original_interface": interface,
            }

            ev = Evidence.from_tool_output(
                tool_name="airmon-ng",
                capability="wireless_interface_management",
                evidence_type=EvidenceType.INTERFACE,
                raw_output=raw_output,
                parsed_data=parsed_data,
                parameters=parameters,
                interface=monitor_iface or interface,
                confidence=ConfidenceLevel.HIGH if exit_code == 0 else ConfidenceLevel.LOW,
                execution_id=self.execution_id,
                raw_command=f"airmon-ng {action} {interface}" if interface else f"airmon-ng {action}",
            )
            evidences.append(ev)

        return evidences

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        action = parameters.get("action", "check")
        if action not in ["check", "start", "stop", "list"]:
            return False, [f"Invalid action {action}, must be check, start, stop, list"]
        if action in ["start", "stop"] and "interface" not in parameters and not parameters.get("interface"):
            # Interface may be passed separately, so check later
            pass
        return True, []


METADATA = ToolCapabilityMetadata(
    name="airmon-ng",
    display_name="airmon-ng - Monitor Mode Management",
    category=CapabilityCategory.WIRELESS_INTERFACE,
    description="Interface and monitor-mode management for wireless assessment",
    tool_binary="airmon-ng",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=["root"],
        dependencies=["iw"],
    ),
    inputs=["action", "optional_interface", "optional_channel"],
    outputs=["interfaces", "monitor_interface"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.CONFIGURATION,
        persistent=False,
        estimated_duration_seconds=5,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=[
        "interface_unavailable",
        "unsupported_driver",
        "insufficient_privileges",
        "invalid_parameters",
    ],
    tags=["monitor", "interface", "aircrack"],
)


ADAPTER_CLASS = AirmonNgAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
