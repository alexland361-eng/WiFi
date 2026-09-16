"""
Adapter for `aireplay-ng` - frame injection and active wireless testing.

Deep research: https://www.aircrack-ng.org/doku.php?id=aireplay-ng

Real usage:
  aireplay-ng --test wlan0mon
  aireplay-ng -0 1 -a 00:11:22:33:44:55 wlan0mon
  aireplay-ng -0 5 -a 00:11:22:33:44:55 -c 11:22:33:44:55:66 wlan0mon
  aireplay-ng -1 0 -a 00:11:22:33:44:55 wlan0mon
  aireplay-ng -3 -b 00:11:22:33:44:55 wlan0mon

Highly invasive, requires monitor + injection, authorization critical.
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


class AireplayNgAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        if not interface:
            raise ValueError("Interface required for aireplay-ng")

        action = parameters.get("action", "test")  # test, deauth, fakeauth, arpreplay

        if action == "test":
            return ["aireplay-ng", "--test", interface]
        elif action == "deauth":
            bssid = parameters.get("bssid") or parameters.get("target_bssid")
            if not bssid:
                raise ValueError("BSSID required for deauth")
            count = parameters.get("count", "1")
            cmd = ["aireplay-ng", "-0", str(count), "-a", bssid, interface]
            client = parameters.get("client_mac") or parameters.get("client")
            if client:
                cmd.extend(["-c", client])
            return cmd
        elif action == "fakeauth":
            bssid = parameters.get("bssid") or parameters.get("target_bssid")
            if not bssid:
                raise ValueError("BSSID required for fakeauth")
            delay = parameters.get("delay", "0")
            return ["aireplay-ng", "-1", str(delay), "-a", bssid, interface]
        elif action == "arpreplay":
            bssid = parameters.get("bssid") or parameters.get("target_bssid")
            if not bssid:
                raise ValueError("BSSID required for arpreplay")
            return ["aireplay-ng", "-3", "-b", bssid, interface]
        else:
            # Default injection test
            return ["aireplay-ng", "-9", interface]

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed = {
            "interface": interface,
            "action": parameters.get("action", "test"),
            "bssid": parameters.get("bssid") or parameters.get("target_bssid"),
        }

        # Parse injection test result
        if "Injection is working" in combined:
            parsed["injection_working"] = True
            parsed["supports_injection"] = True
        elif "Injection is not working" in combined or "Injection failed" in combined:
            parsed["injection_working"] = False
            parsed["supports_injection"] = False

        # Parse deauth
        if "DeAuth" in combined or "deauth" in combined.lower():
            parsed["deauth_sent"] = True
            # Count acks
            m = re.search(r"(\d+)\s+acks", combined, re.IGNORECASE)
            if m:
                parsed["acks"] = int(m.group(1))

        # Check for AP not found
        if "No such BSSID" in combined or "not found" in combined.lower():
            parsed["bssid_not_found"] = True

        confidence = ConfidenceLevel.HIGH if exit_code == 0 else ConfidenceLevel.LOW
        if parsed.get("injection_working") is True:
            confidence = ConfidenceLevel.HIGH

        ev = Evidence.from_tool_output(
            tool_name="aireplay-ng",
            capability="active_wireless_testing",
            evidence_type=EvidenceType.GENERIC,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=confidence,
            execution_id=self.execution_id,
            raw_command=f"aireplay-ng --test {interface}" if interface else "aireplay-ng",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        action = parameters.get("action", "test")
        if action not in ["test", "deauth", "fakeauth", "arpreplay", "injection_test"]:
            return False, [f"Invalid action {action}"]
        if action in ["deauth", "fakeauth", "arpreplay"]:
            bssid = parameters.get("bssid") or parameters.get("target_bssid")
            if not bssid:
                return False, [f"BSSID required for {action}"]
            from ....utils.validation import validate_mac

            valid, msg = validate_mac(bssid)
            if not valid:
                return False, [f"BSSID: {msg}"]
        return True, []

    def custom_requirement_check(self, interface: str | None, parameters: Dict[str, Any]):
        if not interface:
            return False, "Interface required for aireplay-ng"
        return True, ""


METADATA = ToolCapabilityMetadata(
    name="aireplay-ng",
    display_name="aireplay-ng - Active Wireless Testing",
    category=CapabilityCategory.WIRELESS_OBSERVATION,
    description="Frame injection and active wireless testing - highly invasive, requires explicit authorization",
    tool_binary="aireplay-ng",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=True,
        interface_capabilities=["monitor_mode", "injection"],
        privileges=["root"],
    ),
    inputs=["interface", "action", "optional_bssid", "optional_client_mac", "optional_count"],
    outputs=["injection_test", "generic"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_TESTING,
        persistent=False,
        estimated_duration_seconds=10,
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
    tags=["injection", "deauth", "aircrack", "active"],
    references=["https://www.aircrack-ng.org/doku.php?id=aireplay-ng"],
)

ADAPTER_CLASS = AireplayNgAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
