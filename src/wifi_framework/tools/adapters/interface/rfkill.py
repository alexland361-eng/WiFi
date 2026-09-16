"""
Adapter for `rfkill` - radio block management.
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


class RfkillAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        action = parameters.get("action", "list")
        if action == "list":
            return ["rfkill", "list"]
        elif action == "unblock":
            target = parameters.get("target", "wifi")
            return ["rfkill", "unblock", target]
        elif action == "block":
            target = parameters.get("target", "wifi")
            return ["rfkill", "block", target]
        else:
            return ["rfkill", "list"]

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        if exit_code != 0 and not raw_output:
            return []

        evidences = []
        action = parameters.get("action", "list")

        if action == "list":
            # Parse rfkill list
            # Example:
            # 0: phy0: Wireless LAN
            #     Soft blocked: no
            #     Hard blocked: no
            current = None
            devices = []

            for line in raw_output.splitlines():
                line = line.strip()
                if not line:
                    if current:
                        devices.append(current)
                        current = None
                    continue

                m = re.match(r"(\d+):\s+(\S+):\s+(.*)", line)
                if m:
                    if current:
                        devices.append(current)
                    current = {
                        "id": int(m.group(1)),
                        "name": m.group(2),
                        "type": m.group(3),
                        "soft_blocked": False,
                        "hard_blocked": False,
                    }
                    continue

                if current:
                    if "Soft blocked" in line:
                        current["soft_blocked"] = "yes" in line.lower()
                    if "Hard blocked" in line:
                        current["hard_blocked"] = "yes" in line.lower()

            if current:
                devices.append(current)

            for dev in devices:
                ev = Evidence.from_tool_output(
                    tool_name="rfkill",
                    capability="radio_management",
                    evidence_type=EvidenceType.RADIO_BLOCK,
                    raw_output=raw_output,
                    parsed_data=dev,
                    parameters=parameters,
                    interface=interface,
                    confidence=ConfidenceLevel.HIGH,
                    execution_id=self.execution_id,
                    raw_command="rfkill list",
                )
                evidences.append(ev)

        else:
            ev = Evidence.from_tool_output(
                tool_name="rfkill",
                capability="radio_management",
                evidence_type=EvidenceType.RADIO_BLOCK,
                raw_output=raw_output,
                parsed_data={"action": action, "target": parameters.get("target")},
                parameters=parameters,
                interface=interface,
                confidence=ConfidenceLevel.MEDIUM,
                execution_id=self.execution_id,
                raw_command=f"rfkill {action} {parameters.get('target', 'wifi')}",
            )
            evidences.append(ev)

        return evidences

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        action = parameters.get("action", "list")
        if action not in ["list", "block", "unblock"]:
            return False, [f"Invalid action {action}"]
        return True, []


METADATA = ToolCapabilityMetadata(
    name="rfkill",
    display_name="rfkill - Radio Block Management",
    category=CapabilityCategory.RADIO_MANAGEMENT,
    description="Determine whether wireless radios are blocked and manage radio-blocking state",
    tool_binary="rfkill",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["action", "optional_target"],
    outputs=["radio_block_status"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.CONFIGURATION,
        persistent=False,
        estimated_duration_seconds=2,
        invasive=False,
        requires_authorization=False,
    ),
    failure_conditions=["insufficient_privileges", "tool_not_found"],
    tags=["radio", "block"],
)

ADAPTER_CLASS = RfkillAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
