"""
Capability model - machine-readable metadata for every registered tool.

Every registered tool exposes its requirements, inputs, outputs, operational properties,
and failure conditions so planner can determine usability.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class OperatingSystem(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    DARWIN = "darwin"


class InterfaceRequirement(str, Enum):
    NONE = "none"
    REQUIRED = "required"
    MONITOR_MODE = "monitor_mode"
    INJECTION = "injection"


class CapabilityCategory(str, Enum):
    WIRELESS_INTERFACE = "wireless_interface"
    RADIO_MANAGEMENT = "radio_management"
    WIRELESS_OBSERVATION = "wireless_observation"
    WPS_DISCOVERY = "wps_discovery"
    PACKET_CAPTURE = "packet_capture"
    PROTOCOL_ANALYSIS = "protocol_analysis"
    WPS_ASSESSMENT = "wps_assessment"
    WPA_ASSESSMENT = "wpa_assessment"
    NETWORK_DISCOVERY = "network_discovery"
    SERVICE_ENUMERATION = "service_enumeration"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    FRAMEWORK = "framework"
    CREDENTIAL_ASSESSMENT = "credential_assessment"


class OperationalMode(str, Enum):
    ACTIVE_OBSERVATION = "active_observation"
    PASSIVE_OBSERVATION = "passive_observation"
    ACTIVE_TESTING = "active_testing"
    OFFLINE_ANALYSIS = "offline_analysis"
    CONFIGURATION = "configuration"


@dataclass
class CapabilityRequirements:
    """Prerequisites for a capability to be usable."""
    operating_systems: List[OperatingSystem] = field(default_factory=lambda: [OperatingSystem.LINUX])
    interface_required: bool = False
    interface_capabilities: List[str] = field(default_factory=list)  # e.g., monitor_mode, injection
    privileges: List[str] = field(default_factory=list)  # e.g., root, net_admin
    min_tool_version: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)  # other tools/libs needed
    hardware: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operating_systems": [os.value for os in self.operating_systems],
            "interface_required": self.interface_required,
            "interface_capabilities": self.interface_capabilities,
            "privileges": self.privileges,
            "min_tool_version": self.min_tool_version,
            "dependencies": self.dependencies,
            "hardware": self.hardware,
        }


@dataclass
class OperationalProperties:
    mode: OperationalMode = OperationalMode.PASSIVE_OBSERVATION
    persistent: bool = False  # Does it run continuously?
    estimated_duration_seconds: Optional[int] = None
    produces_pcap: bool = False
    invasive: bool = False  # Does it send packets / affect environment?
    requires_authorization: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "persistent": self.persistent,
            "estimated_duration_seconds": self.estimated_duration_seconds,
            "produces_pcap": self.produces_pcap,
            "invasive": self.invasive,
            "requires_authorization": self.requires_authorization,
        }


@dataclass
class ToolCapabilityMetadata:
    """
    Machine-readable metadata for a tool capability.

    Example YAML structure from spec:
    tool:
      name: airodump-ng
      category: wireless_observation
    requirements: ...
    inputs: ...
    outputs: ...
    operational_properties: ...
    failure_conditions: ...
    """
    name: str
    display_name: str
    category: CapabilityCategory
    description: str
    tool_binary: str  # actual executable name
    version: str = "1.0"

    requirements: CapabilityRequirements = field(default_factory=CapabilityRequirements)
    inputs: List[str] = field(default_factory=list)  # e.g., interface, channel, observation_scope
    outputs: List[str] = field(default_factory=list)  # e.g., access_points, clients
    operational_properties: OperationalProperties = field(default_factory=OperationalProperties)
    failure_conditions: List[str] = field(default_factory=list)

    # Additional metadata
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": {
                "name": self.name,
                "display_name": self.display_name,
                "category": self.category.value,
                "tool_binary": self.tool_binary,
                "version": self.version,
            },
            "requirements": self.requirements.to_dict(),
            "inputs": self.inputs,
            "outputs": self.outputs,
            "operational_properties": self.operational_properties.to_dict(),
            "failure_conditions": self.failure_conditions,
            "tags": self.tags,
            "references": self.references,
            "description": self.description,
        }

    def is_compatible_with_os(self, current_os: str) -> bool:
        """Check if capability is compatible with current OS string."""
        current_os_lower = current_os.lower()
        for os_req in self.requirements.operating_systems:
            if os_req.value in current_os_lower:
                return True
        return False
