"""
Parser for airodump-ng CSV and netxml output.

airodump-ng can produce CSV with AP and client sections.
"""
from __future__ import annotations

import csv
import io
import re
from typing import Any, Dict, List

from ..core.models.evidence import ConfidenceLevel, Evidence, EvidenceType


def parse_airodump_csv(csv_content: str) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Parse airodump-ng CSV output.

    Format has two sections: APs and clients separated by blank line.
    AP headers: BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
    Client headers: Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
    """
    aps = []
    clients = []

    # Split into AP and client sections
    # airodump-ng CSV sometimes has blank line separating
    sections = []
    current_section_lines = []
    for line in csv_content.splitlines():
        if not line.strip():
            if current_section_lines:
                sections.append("\n".join(current_section_lines))
                current_section_lines = []
            continue
        current_section_lines.append(line)
    if current_section_lines:
        sections.append("\n".join(current_section_lines))

    # First section should be APs, second clients
    for idx, section in enumerate(sections):
        if not section.strip():
            continue
        try:
            reader = csv.DictReader(io.StringIO(section))
            # Check header to determine type
            fieldnames = reader.fieldnames or []
            fieldnames_lower = [f.lower() if f else "" for f in fieldnames]

            # More precise detection: AP section has ESSID as distinct field, client has Station MAC
            # Note: client section also has BSSID and Probed ESSIDs (which contains essid substring)
            # So check for station first
            is_client_section = any("station mac" in f for f in fieldnames_lower)
            # AP section has ESSID but not Station MAC
            is_ap_section = (not is_client_section) and any(f.strip() == "essid" for f in fieldnames_lower)

            for row in reader:
                # Normalize keys: strip spaces
                normalized = {}
                for k, v in row.items():
                    if k is None:
                        continue
                    key = k.strip()
                    normalized[key] = v.strip() if isinstance(v, str) else v

                if is_ap_section or (idx == 0 and not is_client_section):
                    # AP
                    try:
                        bssid = normalized.get("BSSID") or normalized.get("bssid")
                        if not bssid or bssid.lower() == "station mac":
                            continue
                        # Skip client header mistakenly in AP section
                        if "Station MAC" in normalized:
                            continue

                        essid = normalized.get("ESSID") or normalized.get("essid") or ""
                        channel_str = normalized.get("channel") or normalized.get("Channel") or ""
                        privacy = normalized.get("Privacy") or normalized.get("privacy") or ""
                        cipher = normalized.get("Cipher") or normalized.get("cipher") or ""
                        auth = normalized.get("Authentication") or normalized.get("authentication") or ""
                        power = normalized.get("Power") or normalized.get("power") or ""

                        ap_data = {
                            "bssid": bssid.upper() if bssid else "",
                            "ssid": essid,
                            "channel": None,
                            "privacy": privacy,
                            "cipher": cipher,
                            "authentication": auth,
                            "power": None,
                            "beacons": normalized.get("# beacons") or normalized.get("beacons"),
                            "iv": normalized.get("# IV") or normalized.get("IV"),
                            "is_hidden": not bool(essid.strip()) if essid is not None else False,
                        }

                        # Parse channel
                        try:
                            if channel_str:
                                ap_data["channel"] = int(channel_str)
                        except ValueError:
                            pass

                        # Parse power
                        try:
                            if power:
                                ap_data["power"] = int(power)
                                ap_data["signal"] = int(power)
                        except ValueError:
                            pass

                        # Parse encryption
                        encryption = []
                        if privacy:
                            # Privacy can be like "WPA2 WPA2"
                            parts = privacy.split()
                            for p in parts:
                                if p and p not in encryption:
                                    encryption.append(p)
                        ap_data["encryption"] = encryption

                        # Cipher
                        cipher_list = []
                        if cipher:
                            cipher_list = [c.strip() for c in cipher.split(",") if c.strip()]
                        ap_data["cipher_list"] = cipher_list

                        # Auth
                        auth_list = []
                        if auth:
                            auth_list = [a.strip() for a in auth.split(",") if a.strip()]
                        ap_data["auth_list"] = auth_list

                        if ap_data["bssid"]:
                            aps.append(ap_data)
                    except Exception:
                        continue

                else:
                    # Client
                    try:
                        station = normalized.get("Station MAC") or normalized.get("station mac") or normalized.get("BSSID")
                        if not station:
                            continue
                        bssid = normalized.get("BSSID") or normalized.get("bssid") or ""
                        power = normalized.get("Power") or normalized.get("power") or ""
                        probed = normalized.get("Probed ESSIDs") or normalized.get("probed essids") or ""

                        client_data = {
                            "client_mac": station.upper(),
                            "ap_mac": bssid.upper() if bssid else None,
                            "bssid": bssid.upper() if bssid else None,
                            "power": None,
                            "signal": None,
                            "probed_ssid": probed,
                            "packets": normalized.get("# packets") or normalized.get("packets"),
                        }
                        try:
                            if power:
                                client_data["power"] = int(power)
                                client_data["signal"] = int(power)
                        except ValueError:
                            pass

                        if client_data["client_mac"]:
                            clients.append(client_data)
                    except Exception:
                        continue

        except Exception:
            continue

    return aps, clients


def parse_airodump_text(output: str) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Fallback parser for airodump-ng text output (not CSV).

    Tries to extract BSSIDs and clients from screen output.
    """
    aps = []
    clients = []

    # Very basic regex for BSSID lines
    bssid_pattern = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")

    for line in output.splitlines():
        macs = bssid_pattern.findall(line)
        # This is simplistic; real parsing would need column positions
        # For production, we rely on CSV output
        pass

    return aps, clients


def airodump_to_evidences(
    raw_output: str, csv_content: str = None, interface: str = None, execution_id: str = None
) -> List[Evidence]:
    """Convert airodump output to evidences."""
    evidences = []

    # Prefer CSV if available
    content_to_parse = csv_content or raw_output
    aps, clients = parse_airodump_csv(content_to_parse)

    # If CSV parsing failed, try text
    if not aps and not clients:
        aps, clients = parse_airodump_text(raw_output)

    for ap in aps:
        ev = Evidence.from_tool_output(
            tool_name="airodump-ng",
            capability="wireless_observation",
            evidence_type=EvidenceType.ACCESS_POINT,
            raw_output=raw_output,
            parsed_data={
                "bssid": ap.get("bssid"),
                "ssid": ap.get("ssid"),
                "channel": ap.get("channel"),
                "encryption": ap.get("encryption", []),
                "cipher": ap.get("cipher_list", []),
                "authentication": ap.get("auth_list", []),
                "signal": ap.get("signal"),
                "power": ap.get("power"),
                "is_hidden": ap.get("is_hidden", False),
                "privacy": ap.get("privacy"),
            },
            parameters={"interface": interface} if interface else {},
            interface=interface,
            confidence=ConfidenceLevel.HIGH,
            execution_id=execution_id,
            raw_command=f"airodump-ng {interface}",
        )
        evidences.append(ev)

    for client in clients:
        ev = Evidence.from_tool_output(
            tool_name="airodump-ng",
            capability="wireless_observation",
            evidence_type=EvidenceType.CLIENT,
            raw_output=raw_output,
            parsed_data={
                "client_mac": client.get("client_mac"),
                "ap_mac": client.get("ap_mac"),
                "bssid": client.get("bssid"),
                "signal": client.get("signal"),
                "probed_ssid": client.get("probed_ssid"),
            },
            parameters={"interface": interface} if interface else {},
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=execution_id,
            raw_command=f"airodump-ng {interface}",
        )
        evidences.append(ev)

    return evidences
