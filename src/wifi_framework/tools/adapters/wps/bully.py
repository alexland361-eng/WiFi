"""
Adapter for bully - WPS assessment implementation.
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


class BullyAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        if not interface:
            raise ValueError("Interface required for bully")
        bssid = parameters.get("bssid") or parameters.get("target_bssid")
        if not bssid:
            raise ValueError("BSSID required for bully")

        cmd = ["bully", interface, "-b", bssid]

        if parameters.get("channel"):
            cmd.extend(["-c", str(parameters["channel"])])

        if parameters.get("essid"):
            cmd.extend(["-e", parameters["essid"]])

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed = {
            "bssid": parameters.get("bssid") or parameters.get("target_bssid"),
            "interface": interface,
        }

        # Parse bully output
        pin_match = re.search(r"PIN\s*['\"]?\s*(\d+)", combined, re.IGNORECASE)
        if pin_match:
            parsed["wps_pin"] = pin_match.group(1)

        # WPA key
        key_match = re.search(r"Key\s*['\"]?\s*['\"]?(.+?)['\"]?\s*$", combined, re.IGNORECASE | re.MULTILINE)
        if key_match:
            parsed["wpa_psk"] = key_match.group(1).strip()

        ev = Evidence.from_tool_output(
            tool_name="bully",
            capability="wps_assessment",
            evidence_type=EvidenceType.WPS,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.HIGH if parsed.get("wps_pin") else ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"bully {interface} -b {parsed['bssid']}" if parsed.get("bssid") else "bully",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        bssid = parameters.get("bssid") or parameters.get("target_bssid")
        if not bssid:
            return False, ["BSSID required"]
        from ....utils.validation import validate_mac

        valid, msg = validate_mac(bssid)
        if not valid:
            return False, [f"BSSID: {msg}"]
        return True, []


METADATA = ToolCapabilityMetadata(
    name="bully",
    display_name="bully - WPS Assessment",
    category=CapabilityCategory.WPS_ASSESSMENT,
    description="Another WPS assessment implementation",
    tool_binary="bully",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=True,
        interface_capabilities=["monitor_mode"],
        privileges=["root"],
    ),
    inputs=["interface", "bssid", "optional_channel", "optional_essid"],
    outputs=["wps_observations", "credential_observation"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_TESTING,
        persistent=False,
        estimated_duration_seconds=300,
        invasive=True,
        requires_authorization=True,
    ),
    failure_conditions=[
        "interface_unavailable",
        "unsupported_driver",
        "insufficient_privileges",
        "invalid_parameters",
        "timeout",
    ],
    tags=["wps", "assessment"],
)

ADAPTER_CLASS = BullyAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
