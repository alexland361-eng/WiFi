"""
Adapter for macchanger - MAC address configuration/testing.
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


class MacchangerAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        if not interface:
            raise ValueError("Interface required for macchanger")

        action = parameters.get("action", "show")  # show, random, set

        cmd = ["macchanger"]

        if action == "show":
            cmd.extend(["-s", interface])
        elif action == "random":
            cmd.extend(["-r", interface])
        elif action == "set":
            mac = parameters.get("mac")
            if not mac:
                raise ValueError("MAC required for set action")
            cmd.extend(["-m", mac, interface])
        elif action == "reset":
            cmd.extend(["-p", interface])
        else:
            cmd.extend(["-s", interface])

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed = {
            "interface": interface,
            "action": parameters.get("action", "show"),
        }

        # Parse current MAC
        m = re.search(r"Current MAC:\s*([0-9A-Fa-f:]{17})", combined)
        if m:
            parsed["current_mac"] = m.group(1).upper()

        # Permanent MAC
        m = re.search(r"Permanent MAC:\s*([0-9A-Fa-f:]{17})", combined)
        if m:
            parsed["permanent_mac"] = m.group(1).upper()

        ev = Evidence.from_tool_output(
            tool_name="macchanger",
            capability="protocol_analysis",
            evidence_type=EvidenceType.INTERFACE,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.HIGH,
            execution_id=self.execution_id,
            raw_command=f"macchanger -s {interface}" if interface else "macchanger",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        action = parameters.get("action", "show")
        if action not in ["show", "random", "set", "reset"]:
            return False, [f"Invalid action {action}"]
        if action == "set" and not parameters.get("mac"):
            return False, ["MAC required for set action"]
        if action == "set" and parameters.get("mac"):
            from ....utils.validation import validate_mac

            valid, msg = validate_mac(parameters["mac"])
            if not valid:
                return False, [f"MAC: {msg}"]
        return True, []


METADATA = ToolCapabilityMetadata(
    name="macchanger",
    display_name="macchanger - MAC Management",
    category=CapabilityCategory.PROTOCOL_ANALYSIS,
    description="Used for authorized local-interface MAC-address configuration/testing",
    tool_binary="macchanger",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=True,
        privileges=["root"],
    ),
    inputs=["interface", "optional_action", "optional_mac"],
    outputs=["interface"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.CONFIGURATION,
        persistent=False,
        estimated_duration_seconds=3,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["interface_unavailable", "insufficient_privileges", "invalid_parameters"],
    tags=["mac", "interface"],
)

ADAPTER_CLASS = MacchangerAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
