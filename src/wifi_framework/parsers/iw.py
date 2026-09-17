"""
Parser for iw utility output.

iw dev, iw phy, iw list, etc.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..core.models.evidence import ConfidenceLevel, Evidence, EvidenceType


def parse_iw_dev(output: str) -> List[Dict[str, Any]]:
    """
    Parse `iw dev` output.

    Example:
    phy#0
        Interface wlan0
            ifindex 3
            wdev 0x1
            addr 00:11:22:33:44:55
            ssid MyNetwork
            type managed
            channel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
    """
    interfaces = []
    current = None
    phy = None

    for line in output.splitlines():
        line_stripped = line.strip()
        if not line_stripped:
            continue

        phy_match = re.match(r"phy#(\d+)", line_stripped)
        if phy_match:
            phy = phy_match.group(1)
            continue

        iface_match = re.match(r"Interface\s+(\S+)", line_stripped)
        if iface_match:
            if current:
                interfaces.append(current)
            current = {
                "phy": phy,
                "name": iface_match.group(1),
                "type": "unknown",
            }
            continue

        if current is None:
            continue

        # Parse attributes
        if "addr" in line_stripped:
            m = re.search(r"addr\s+([0-9A-Fa-f:]{17})", line_stripped)
            if m:
                current["mac"] = m.group(1).upper()
        if "type" in line_stripped:
            m = re.search(r"type\s+(\w+)", line_stripped)
            if m:
                current["type"] = m.group(1)
        if "channel" in line_stripped:
            m = re.search(r"channel\s+(\d+)", line_stripped)
            if m:
                try:
                    current["channel"] = int(m.group(1))
                except ValueError:
                    pass
            m = re.search(r"\((\d+)\s*MHz\)", line_stripped)
            if m:
                try:
                    current["frequency"] = int(m.group(1))
                except ValueError:
                    pass
        if "ssid" in line_stripped:
            m = re.search(r"ssid\s+(.+)", line_stripped)
            if m:
                current["ssid"] = m.group(1).strip()
        if "ifindex" in line_stripped:
            m = re.search(r"ifindex\s+(\d+)", line_stripped)
            if m:
                current["ifindex"] = int(m.group(1))

    if current:
        interfaces.append(current)

    return interfaces


def parse_iw_list(output: str) -> Dict[str, Any]:
    """
    Parse `iw list` output for capabilities.

    Looks for Supported interface modes, monitor, etc.
    """
    capabilities = {
        "supports_monitor": False,
        "supports_injection": False,  # iw list doesn't directly show injection, but we can infer
        "bands": [],
        "interface_modes": [],
    }

    # Find Supported interface modes section
    in_modes = False
    for line in output.splitlines():
        stripped = line.strip()
        if "Supported interface modes" in stripped:
            in_modes = True
            continue
        if in_modes:
            if stripped.startswith("*"):
                mode = stripped.lstrip("* ").strip()
                capabilities["interface_modes"].append(mode)
                if "monitor" in mode.lower():
                    capabilities["supports_monitor"] = True
            elif stripped and not line.startswith("\t") and not line.startswith(" "):
                # End of modes section
                if capabilities["interface_modes"]:
                    in_modes = False
            elif "Band" in stripped:
                in_modes = False

    # Check for injection via "frame injection" hints or assume if monitor supported
    # Real injection test requires aireplay-ng, but we note monitor as prerequisite
    if capabilities["supports_monitor"]:
        # We can't confirm injection from iw list alone, mark as unknown
        capabilities["injection_test_required"] = True

    return capabilities


def parse_iw_link(output: str) -> Dict[str, Any]:
    """Parse `iw dev <iface> link` output."""
    result = {}
    for line in output.splitlines():
        stripped = line.strip()
        if "SSID:" in stripped:
            result["ssid"] = stripped.split("SSID:")[1].strip()
        if "freq:" in stripped:
            m = re.search(r"freq:\s+(\d+)", stripped)
            if m:
                result["frequency"] = int(m.group(1))
        if "signal:" in stripped:
            m = re.search(r"signal:\s+(-?\d+)\s*dBm", stripped)
            if m:
                result["signal"] = int(m.group(1))
        if "Connected to" in stripped:
            m = re.search(r"Connected to ([0-9A-Fa-f:]{17})", stripped)
            if m:
                result["bssid"] = m.group(1).upper()
    return result


def iw_dev_to_evidences(output: str, interface: Optional[str] = None, execution_id: Optional[str] = None) -> List[Evidence]:
    """Convert iw dev output to evidences."""
    interfaces = parse_iw_dev(output)
    evidences = []
    for iface in interfaces:
        ev = Evidence.from_tool_output(
            tool_name="iw",
            capability="wireless_interface_discovery",
            evidence_type=EvidenceType.INTERFACE,
            raw_output=output,
            parsed_data=iface,
            parameters={"interface": interface} if interface else {},
            interface=iface.get("name"),
            confidence=ConfidenceLevel.HIGH,
            execution_id=execution_id,
            raw_command="iw dev",
        )
        evidences.append(ev)
    return evidences
