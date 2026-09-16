"""
Adapters for aircrack-ng suite: aircrack-ng, airdecap-ng, airbase-ng, etc.

Deep research: https://www.aircrack-ng.org/doku.php

Real usage:
  aircrack-ng -w wordlist.txt capture.cap
  aircrack-ng -w wordlist.txt -b 00:11:22:33:44:55 capture.cap
  airdecap-ng -e MyNetwork -p password capture.cap
  airbase-ng -e FakeAP -c 6 wlan0mon
  wpaclean cleaned.cap capture.cap
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


class AircrackNgAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        capture_file = parameters.get("capture_file") or parameters.get("input_file")
        if not capture_file:
            raise ValueError("capture_file required for aircrack-ng")

        cmd = ["aircrack-ng"]

        wordlist = parameters.get("wordlist")
        if wordlist:
            cmd.extend(["-w", wordlist])

        bssid = parameters.get("bssid") or parameters.get("target_bssid")
        if bssid:
            cmd.extend(["-b", bssid])

        # Mode: -a 2 for WPA
        if parameters.get("mode"):
            cmd.extend(["-a", str(parameters["mode"])])

        cmd.append(capture_file)
        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed = {
            "capture_file": parameters.get("capture_file") or parameters.get("input_file"),
            "bssid": parameters.get("bssid"),
        }

        # Parse KEY FOUND
        m = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", combined)
        if m:
            parsed["key_found"] = m.group(1).strip()
            parsed["success"] = True
        else:
            parsed["success"] = False

        # Parse BSSID
        m = re.search(r"([0-9A-Fa-f:]{17}).*WPA", combined)
        if m:
            parsed["found_bssid"] = m.group(1).upper()

        ev = Evidence.from_tool_output(
            tool_name="aircrack-ng",
            capability="credential_assessment",
            evidence_type=EvidenceType.CREDENTIAL,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.HIGH if parsed.get("success") else ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"aircrack-ng {parsed['capture_file']}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("capture_file") and not parameters.get("input_file"):
            return False, ["capture_file required"]
        return True, []


class AirdecapNgAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        capture_file = parameters.get("capture_file") or parameters.get("input_file")
        if not capture_file:
            raise ValueError("capture_file required for airdecap-ng")

        cmd = ["airdecap-ng"]

        essid = parameters.get("essid") or parameters.get("ssid")
        if essid:
            cmd.extend(["-e", essid])

        bssid = parameters.get("bssid")
        if bssid:
            cmd.extend(["-b", bssid])

        password = parameters.get("password") or parameters.get("key")
        if password:
            cmd.extend(["-p", password])

        # WEP key
        if parameters.get("w"):
            cmd.extend(["-w", parameters["w"]])

        cmd.append(capture_file)
        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed = {
            "capture_file": parameters.get("capture_file") or parameters.get("input_file"),
            "success": exit_code == 0,
        }

        # Parse decrypted packets count
        m = re.search(r"(\d+)\s+packets\s+decrypted", combined, re.IGNORECASE)
        if m:
            parsed["decrypted_count"] = int(m.group(1))

        ev = Evidence.from_tool_output(
            tool_name="airdecap-ng",
            capability="capture_decryption",
            evidence_type=EvidenceType.CAPTURE,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.HIGH if exit_code == 0 else ConfidenceLevel.LOW,
            execution_id=self.execution_id,
            raw_command=f"airdecap-ng {parsed['capture_file']}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("capture_file") and not parameters.get("input_file"):
            return False, ["capture_file required"]
        return True, []


# Metadata
AIRCRACK_METADATA = ToolCapabilityMetadata(
    name="aircrack-ng",
    display_name="aircrack-ng - Key Recovery",
    category=CapabilityCategory.CREDENTIAL_ASSESSMENT,
    description="Capture analysis and authorized key-recovery testing",
    tool_binary="aircrack-ng",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["capture_file", "optional_wordlist", "optional_bssid", "optional_mode"],
    outputs=["credential_observation"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.OFFLINE_ANALYSIS,
        persistent=False,
        estimated_duration_seconds=60,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found", "invalid_parameters"],
    tags=["wpa", "cracking", "aircrack"],
    references=["https://www.aircrack-ng.org/doku.php?id=aircrack-ng"],
)

AIRDECAP_METADATA = ToolCapabilityMetadata(
    name="airdecap-ng",
    display_name="airdecap-ng - Capture Decryption",
    category=CapabilityCategory.WPA_ASSESSMENT,
    description="Authorized capture decryption when required credentials available",
    tool_binary="airdecap-ng",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["capture_file", "optional_essid", "optional_bssid", "optional_password"],
    outputs=["capture"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.OFFLINE_ANALYSIS,
        persistent=False,
        estimated_duration_seconds=10,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found", "invalid_parameters"],
    tags=["decrypt", "aircrack"],
    references=["https://www.aircrack-ng.org/doku.php?id=airdecap-ng"],
)


def register(registry):
    registry.register(AIRCRACK_METADATA, AircrackNgAdapter)
    registry.register(AIRDECAP_METADATA, AirdecapNgAdapter)
