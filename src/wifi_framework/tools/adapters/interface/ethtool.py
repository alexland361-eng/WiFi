"""
Adapter for `ethtool` - interface and driver information.
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


class EthtoolAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        if not interface:
            raise ValueError("Interface required for ethtool")
        info_type = parameters.get("info_type", "info")  # info, driver, etc.
        if info_type == "driver":
            return ["ethtool", "-i", interface]
        else:
            return ["ethtool", interface]

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        if exit_code != 0 and not raw_output:
            return []

        parsed = {}
        for line in raw_output.splitlines():
            if ":" in line:
                parts = line.split(":", 1)
                key = parts[0].strip().lower().replace(" ", "_")
                value = parts[1].strip()
                parsed[key] = value

        # Special handling for driver info
        if "driver" in parsed:
            parsed["driver_name"] = parsed["driver"]

        ev = Evidence.from_tool_output(
            tool_name="ethtool",
            capability="wireless_interface_discovery",
            evidence_type=EvidenceType.DRIVER_INFO,
            raw_output=raw_output,
            parsed_data={"interface": interface, **parsed},
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"ethtool {interface}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


METADATA = ToolCapabilityMetadata(
    name="ethtool",
    display_name="ethtool - Driver and Interface Info",
    category=CapabilityCategory.WIRELESS_INTERFACE,
    description="Provides lower-level interface and driver information for diagnostics",
    tool_binary="ethtool",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=True,
        privileges=[],
    ),
    inputs=["interface", "optional_info_type"],
    outputs=["driver_info", "interface_info"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.PASSIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=2,
        invasive=False,
        requires_authorization=False,
    ),
    failure_conditions=["interface_unavailable", "tool_not_found"],
    tags=["driver", "interface"],
)

ADAPTER_CLASS = EthtoolAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
