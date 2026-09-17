"""
Adapter for `iw` - Linux low-level wireless configuration and information utility.
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
from ....parsers.iw import iw_dev_to_evidences, parse_iw_list


class IwDevAdapter(ToolAdapterBase):
    """Adapter for `iw dev` - interface discovery."""

    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        # iw dev shows all interfaces, or specific interface info
        if interface and parameters.get("subcommand") == "link":
            return ["iw", "dev", interface, "link"]
        elif interface and parameters.get("subcommand") == "info":
            return ["iw", "dev", interface, "info"]
        else:
            return ["iw", "dev"]

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        if exit_code != 0:
            return []
        # iw dev output
        return iw_dev_to_evidences(raw_output, interface=interface, execution_id=self.execution_id)

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


class IwListAdapter(ToolAdapterBase):
    """Adapter for `iw list` - capability discovery."""

    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        if interface and parameters.get("phy"):
            return ["iw", "phy", parameters["phy"], "info"]
        return ["iw", "list"]

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        if exit_code != 0:
            return []
        caps = parse_iw_list(raw_output)
        from ....core.models.evidence import ConfidenceLevel, EvidenceType

        ev = Evidence.from_tool_output(
            tool_name="iw",
            capability="wireless_capability_discovery",
            evidence_type=EvidenceType.INTERFACE,
            raw_output=raw_output,
            parsed_data=caps,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.HIGH,
            execution_id=self.execution_id,
            raw_command="iw list",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


# Metadata definitions
IW_DEV_METADATA = ToolCapabilityMetadata(
    name="iw_dev",
    display_name="iw dev - Wireless Interface Discovery",
    category=CapabilityCategory.WIRELESS_INTERFACE,
    description="Inspect wireless interfaces, wireless capabilities, channels, PHY information, and interface state using iw",
    tool_binary="iw",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["optional_interface", "optional_subcommand"],
    outputs=["interfaces", "channels", "signal_observations"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.PASSIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=2,
        invasive=False,
        requires_authorization=False,
    ),
    failure_conditions=["interface_unavailable", "insufficient_privileges", "tool_not_found"],
    tags=["interface", "discovery", "iw"],
)

IW_LIST_METADATA = ToolCapabilityMetadata(
    name="iw_list",
    display_name="iw list - PHY Capability Discovery",
    category=CapabilityCategory.WIRELESS_INTERFACE,
    description="Discover PHY capabilities including monitor mode support",
    tool_binary="iw",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["optional_phy"],
    outputs=["interface_capabilities", "monitor_mode_support"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.PASSIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=3,
        invasive=False,
        requires_authorization=False,
    ),
    failure_conditions=["insufficient_privileges", "tool_not_found"],
    tags=["capability", "phy", "monitor"],
)

# For registry auto-discovery
METADATA = IW_DEV_METADATA
ADAPTER_CLASS = IwDevAdapter


def register(registry):
    registry.register(IW_DEV_METADATA, IwDevAdapter)
    registry.register(IW_LIST_METADATA, IwListAdapter)
