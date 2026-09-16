"""
Adapter for reaver - WPS security assessment.
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


class ReaverAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        if not interface:
            raise ValueError("Interface required for reaver")
        bssid = parameters.get("bssid") or parameters.get("target_bssid")
        if not bssid:
            raise ValueError("BSSID required for reaver")

        cmd = ["reaver", "-i", interface, "-b", bssid]

        if parameters.get("channel"):
            cmd.extend(["-c", str(parameters["channel"])])

        if parameters.get("ssid"):
            cmd.extend(["-e", parameters["ssid"]])

        # Additional options
        if parameters.get("no_nacks"):
            cmd.append("-N")

        if parameters.get("pin"):
            cmd.extend(["-p", parameters["pin"]])

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        # Parse reaver output for WPS pin, WPA PSK, etc.
        parsed = {
            "bssid": parameters.get("bssid") or parameters.get("target_bssid"),
            "interface": interface,
        }

        # Look for WPS PIN
        pin_match = re.search(r"WPS PIN:\s*['\"]?(\d+)['\"]?", combined, re.IGNORECASE)
        if pin_match:
            parsed["wps_pin"] = pin_match.group(1)

        # Look for WPA PSK
        psk_match = re.search(r"WPA PSK:\s*['\"]?(.+?)['\"]?\s*$", combined, re.IGNORECASE | re.MULTILINE)
        if psk_match:
            parsed["wpa_psk"] = psk_match.group(1).strip()

        # Look for AP SSID
        ssid_match = re.search(r"AP SSID:\s*['\"]?(.+?)['\"]?\s*$", combined, re.IGNORECASE | re.MULTILINE)
        if ssid_match:
            parsed["ssid"] = ssid_match.group(1).strip()

        # Check if WPS locked
        if "WPS transaction failed" in combined or "AP rate limiting" in combined:
            parsed["wps_locked"] = True

        ev = Evidence.from_tool_output(
            tool_name="reaver",
            capability="wps_assessment",
            evidence_type=EvidenceType.WPS,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.HIGH if parsed.get("wps_pin") else ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"reaver -i {interface} -b {parsed['bssid']}" if parsed.get("bssid") else "reaver",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        errors = []
        bssid = parameters.get("bssid") or parameters.get("target_bssid")
        if not bssid:
            errors.append("BSSID required")
        else:
            from ....utils.validation import validate_mac

            valid, msg = validate_mac(bssid)
            if not valid:
                errors.append(f"BSSID: {msg}")
        return (False, errors) if errors else (True, [])


METADATA = ToolCapabilityMetadata(
    name="reaver",
    display_name="reaver - WPS Assessment",
    category=CapabilityCategory.WPS_ASSESSMENT,
    description="WPS security assessment tool",
    tool_binary="reaver",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=True,
        interface_capabilities=["monitor_mode"],
        privileges=["root"],
    ),
    inputs=["interface", "bssid", "optional_channel", "optional_ssid", "optional_pin"],
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

ADAPTER_CLASS = ReaverAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
