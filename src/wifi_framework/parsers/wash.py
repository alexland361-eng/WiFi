"""
Parser for wash - WPS discovery tool.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..core.models.evidence import ConfidenceLevel, Evidence, EvidenceType


def parse_wash(output: str) -> List[Dict[str, Any]]:
    """
    Parse wash output.

    Example:
    BSSID              Ch  dBm  WPS  Lck  Vendor    ESSID
    00:11:22:33:44:55  6   -45  2.0  No   Broadcom  MyNetwork
    """
    results = []

    # Find header line
    lines = output.splitlines()
    header_found = False
    for line in lines:
        if "BSSID" in line and "ESSID" in line:
            header_found = True
            continue
        if not header_found:
            continue
        if not line.strip():
            continue
        # Skip separator lines
        if line.strip().startswith("-"):
            continue

        # Parse WPS line
        # BSSID (17 chars) + rest
        # Use regex
        # BSSID, Ch, dBm, WPS version, Lck, Vendor, ESSID
        pattern = re.compile(
            r"^\s*([0-9A-Fa-f:]{17})\s+(\d+)\s+(-?\d+)\s+([\d\.]+|n/a)\s+(\w+)\s+(\S+)?\s*(.*)?$"
        )
        m = pattern.match(line)
        if m:
            bssid = m.group(1).upper()
            channel = m.group(2)
            dbm = m.group(3)
            wps_version = m.group(4)
            locked = m.group(5)
            vendor = m.group(6) or ""
            essid = m.group(7) or ""

            try:
                channel_int = int(channel)
            except ValueError:
                channel_int = None

            try:
                signal = int(dbm)
            except ValueError:
                signal = None

            wps_enabled = wps_version.lower() != "n/a" and wps_version != ""

            results.append(
                {
                    "bssid": bssid,
                    "channel": channel_int,
                    "signal": signal,
                    "power": signal,
                    "wps_version": wps_version,
                    "wps_enabled": wps_enabled,
                    "wps_locked": locked.lower() == "yes",
                    "vendor": vendor,
                    "ssid": essid.strip(),
                    "manufacturer": vendor,
                }
            )
        else:
            # Fallback: try simple split
            parts = line.split()
            if len(parts) >= 1:
                maybe_bssid = parts[0]
                if re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", maybe_bssid):
                    results.append(
                        {
                            "bssid": maybe_bssid.upper(),
                            "raw_line": line.strip(),
                            "wps_enabled": True,  # If listed by wash, WPS is present
                        }
                    )

    return results


def wash_to_evidences(output: str, interface: Optional[str] = None, execution_id: Optional[str] = None) -> List[Evidence]:
    evidences = []
    parsed = parse_wash(output)
    for entry in parsed:
        ev = Evidence.from_tool_output(
            tool_name="wash",
            capability="wps_discovery",
            evidence_type=EvidenceType.WPS,
            raw_output=output,
            parsed_data=entry,
            parameters={"interface": interface} if interface else {},
            interface=interface,
            confidence=ConfidenceLevel.HIGH,
            execution_id=execution_id,
            raw_command=f"wash -i {interface}" if interface else "wash",
        )
        evidences.append(ev)
    return evidences
