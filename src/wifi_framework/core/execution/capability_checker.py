"""
Capability checker - verifies interface, OS, driver, privileges, tool version, environment.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

from ..models.capability import ToolCapabilityMetadata
from ...utils.system import (
    check_interface_exists,
    check_tool_available,
    effective_capabilities,
    get_os_info,
    is_root,
    satisfies_privileges,
)


class CapabilityChecker:
    """Checks if capability is usable in current environment."""

    def __init__(self):
        self.os_info = get_os_info()
        self.is_root = is_root()
        #: Capabilities actually held. ``is_root`` alone cannot express a process
        #: running unprivileged with CAP_NET_ADMIN, which is a normal and sufficient
        #: way to administer wireless interfaces.
        self.capabilities = sorted(effective_capabilities())

    def check(self, capability: ToolCapabilityMetadata, interface: Optional[str] = None) -> Tuple[bool, str, Dict]:
        """
        Check capability availability.

        Returns (available, reason, details)
        """
        details = {
            "os": self.os_info,
            "is_root": self.is_root,
            "capabilities": list(self.capabilities),
            "tool_binary": capability.tool_binary,
        }

        # OS check
        if not capability.is_compatible_with_os(self.os_info["system"]):
            return False, f"Incompatible OS: {self.os_info['system']}", details

        # Tool availability
        available, path, version = check_tool_available(capability.tool_binary)
        details["tool_path"] = path
        details["tool_version_raw"] = version
        if not available:
            return False, f"Tool '{capability.tool_binary}' not found", details

        # Privileges
        privileges_ok, privilege_reason = satisfies_privileges(capability.requirements.privileges)
        if not privileges_ok:
            return False, privilege_reason, details

        # Interface
        if capability.requirements.interface_required:
            if not interface:
                return False, "Interface required but not specified", details
            if not check_interface_exists(interface):
                return False, f"Interface {interface} does not exist", details
            details["interface_exists"] = True

            # Check interface capabilities if specified
            # For monitor_mode and injection, we'd need deeper checks (iw, etc.)
            # For now, we report as unknown but not failing
            details["interface_capabilities_requested"] = capability.requirements.interface_capabilities

        # Dependencies
        for dep in capability.requirements.dependencies:
            dep_avail, _, _ = check_tool_available(dep)
            if not dep_avail:
                return False, f"Dependency {dep} not available", details

        return True, "Available", details
