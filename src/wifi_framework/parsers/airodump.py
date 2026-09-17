"""
Parser for airodump-ng CSV and netxml output.

airodump-ng can produce CSV with AP and client sections.
"""
from __future__ import annotations

import csv
import io
import re
from typing import Any, Dict, List, Optional, Sequence

from ..core.models.evidence import ConfidenceLevel, Evidence, EvidenceType


def _note(issues: Optional[List[str]], message: str) -> None:
    """Append a parsing problem to the caller's list, if the caller wants them.

    A parser that returns an empty result and a parser that failed look identical to
    the caller, so the difference has to travel out of band. ``issues`` is optional so
    existing callers are unaffected.
    """
    if issues is not None:
        issues.append(message)


#: Screen-output tables. airodump-ng reorders and adds columns between versions (newer
#: builds print ``PWR RXQ`` where older print only ``PWR``), so field offsets are read
#: from the header the tool actually printed rather than assumed.
_AP_TABLE_COLUMNS: Sequence[str] = ("PWR", "CH", "ENC", "Privacy", "CIPHER", "AUTH", "ESSID")
#: The station table's trailing fields (``Notes``, ``Probes``) are where offset slicing
#: stops being trustworthy: airodump-ng prints a ``Rate`` containing a space
#: (``0e- 1``) and the probe text does not start under its header, so reading them
#: yields a truncated SSID rather than the real one. A wrong SSID attached to a client
#: is worse than an absent one - it becomes evidence, and it is fabricated. Only PWR is
#: read here; the CSV writer, which is the authoritative source, provides the rest.
_STATION_TABLE_COLUMNS: Sequence[str] = ("PWR",)

_MAC_ONLY = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def _column_offsets(header: str, names: Sequence[str]) -> Dict[str, int]:
    """Character offset of each named column in a screen-output header line."""
    offsets = {}
    for name in names:
        found = header.find(name)
        if found >= 0:
            offsets[name] = found
    return offsets


def _leading_token(row: str, offsets: Dict[str, int], name: str) -> str:
    """The first whitespace-delimited token in ``name``'s span.

    The span runs to the next *recognized* column, so unnamed columns printed between
    two recognized ones land inside it: ``CH   MB   ENC`` puts ``MB`` in CH's span, and
    slicing the whole span gives ``"11  130"``, which is not a channel. The column's own
    value is always the first token, because airodump-ng pads columns to fixed width.
    """
    return _column_value(row, offsets, name).split()[0] if _column_value(row, offsets, name) else ""


def _column_value(row: str, offsets: Dict[str, int], name: str) -> str:
    """The slice of ``row`` belonging to ``name``, or "" if that column was not printed.

    Slicing at header offsets rather than splitting on whitespace is what makes this
    work across versions, and it is also the only way to read an ESSID containing
    spaces, which is common and would otherwise consume the following columns.
    """
    start = offsets.get(name)
    if start is None:
        return ""
    later = [offset for offset in sorted(set(offsets.values())) if offset > start]
    return row[start:later[0]].strip() if later else row[start:].strip()


def parse_airodump_csv(
    csv_content: str, issues: Optional[List[str]] = None
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Parse airodump-ng CSV output.

    Format has two sections: APs and clients separated by blank line.
    AP headers: BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
    Client headers: Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
    """
    aps: List[Dict[str, Any]] = []
    clients: List[Dict[str, Any]] = []

    # Split into AP and client sections
    # airodump-ng CSV sometimes has blank line separating
    sections = []
    current_section_lines: List[str] = []
    for line in csv_content.splitlines():
        if not line.strip():
            if current_section_lines:
                sections.append("\n".join(current_section_lines))
                current_section_lines = []
            continue
        current_section_lines.append(line)
    if current_section_lines:
        sections.append("\n".join(current_section_lines))

    if not sections:
        _note(issues, "airodump-ng CSV output was empty; no AP or client rows to parse")
        return aps, clients

    recognized_sections = 0
    unreadable_rows = 0

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

            if is_client_section or is_ap_section:
                recognized_sections += 1
            elif idx > 0:
                # Section 0 is parsed as an AP table even without a recognizable header,
                # because airodump-ng omits no header it always prints. Later sections
                # that match nothing are not guessed at.
                _note(
                    issues,
                    f"airodump-ng CSV section {idx + 1} has no recognized header "
                    f"(found {fieldnames[:4]}); it was not parsed",
                )
                continue

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
                    except Exception as exc:
                        unreadable_rows += 1
                        _note(
                            issues,
                            f"airodump-ng CSV AP row could not be parsed "
                            f"({type(exc).__name__}: {exc})",
                        )
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
                    except Exception as exc:
                        unreadable_rows += 1
                        _note(
                            issues,
                            f"airodump-ng CSV client row could not be parsed "
                            f"({type(exc).__name__}: {exc})",
                        )
                        continue

        except Exception as exc:
            _note(
                issues,
                f"airodump-ng CSV section {idx + 1} could not be parsed "
                f"({type(exc).__name__}: {exc})",
            )
            continue

    if recognized_sections == 0:
        _note(
            issues,
            "no airodump-ng CSV header (BSSID/ESSID or Station MAC) was found in the "
            "supplied output; nothing was parsed",
        )
    elif not aps and not clients:
        _note(
            issues,
            f"airodump-ng CSV headers were present but no usable rows were extracted "
            f"({unreadable_rows} unreadable)",
        )

    return aps, clients


def parse_airodump_text(
    output: str, issues: Optional[List[str]] = None
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Fallback parser for airodump-ng screen output (not CSV).

    The CSV writer is the authoritative source: it is machine-readable and version
    stable. This exists for runs where no ``--write`` file was found, and it is
    best-effort - it reads the on-screen tables using the column offsets in the header
    airodump-ng printed, which is what lets it survive the layout changes between
    versions. Callers should surface the returned issues, because a screen parse that
    finds nothing and a radio that genuinely sees nothing are otherwise
    indistinguishable.
    """
    aps: List[Dict[str, Any]] = []
    clients: List[Dict[str, Any]] = []

    ap_offsets: Dict[str, int] = {}
    station_offsets: Dict[str, int] = {}
    in_station_table = False
    mac_lines_seen = 0
    station_fields_skipped = False

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("BSSID") and "ESSID" in stripped and "seen" not in stripped:
            ap_offsets = _column_offsets(line, _AP_TABLE_COLUMNS)
            in_station_table = False
            continue

        if stripped.startswith("Station"):
            station_offsets = _column_offsets(line, _STATION_TABLE_COLUMNS)
            in_station_table = True
            continue

        first_token = stripped.split()[0]
        if not _MAC_ONLY.match(first_token):
            continue

        mac_lines_seen += 1

        if in_station_table and station_offsets:
            power = _to_int(_leading_token(line, station_offsets, "PWR"))
            clients.append(
                {
                    "client_mac": first_token.upper(),
                    "ap_mac": None,
                    "bssid": None,
                    "power": power,
                    "signal": power,
                    "probed_ssid": None,
                    "packets": None,
                }
            )
            station_fields_skipped = True
            continue

        if not ap_offsets:
            # A MAC-bearing line outside any recognized table: the output has data this
            # parser cannot attribute to a column layout.
            continue

        # ESSID is the trailing column and is read as a whole span, not a token: SSIDs
        # routinely contain spaces, and taking the first token would truncate them.
        essid = _column_value(line, ap_offsets, "ESSID")
        privacy = _leading_token(line, ap_offsets, "ENC") or _leading_token(line, ap_offsets, "Privacy")
        cipher = _leading_token(line, ap_offsets, "CIPHER")
        auth = _leading_token(line, ap_offsets, "AUTH")
        power = _to_int(_leading_token(line, ap_offsets, "PWR"))
        channel = _to_int(_leading_token(line, ap_offsets, "CH"))

        aps.append(
            {
                "bssid": first_token.upper(),
                "ssid": "" if essid.startswith("<length:") else essid,
                "channel": channel,
                "privacy": privacy,
                "cipher": cipher,
                "authentication": auth,
                "power": power,
                "signal": power,
                "beacons": None,
                "iv": None,
                "is_hidden": not essid.strip() or essid.startswith("<length:"),
                "encryption": [part for part in privacy.split() if part],
                "cipher_list": [part.strip() for part in cipher.split(",") if part.strip()],
                "auth_list": [part.strip() for part in auth.split(",") if part.strip()],
            }
        )

    if station_fields_skipped:
        _note(
            issues,
            "client rows came from airodump-ng screen output, which does not reliably "
            "attribute probe requests or associations; those fields are left unset rather "
            "than guessed, and the CSV writer (--write) provides them",
        )

    if mac_lines_seen and not aps and not clients:
        _note(
            issues,
            f"airodump-ng screen output contained {mac_lines_seen} MAC address line(s) but no "
            "recognizable table header, so nothing could be attributed to a column; the "
            "capture was not empty",
        )
    elif not mac_lines_seen:
        _note(
            issues,
            "airodump-ng screen output contained no MAC address lines; either nothing was "
            "observed or the output was not airodump-ng screen output",
        )

    return aps, clients


def _to_int(value: str) -> Optional[int]:
    """An int from a screen-output field, or ``None`` when the column held something else.

    airodump-ng prints non-numeric markers in numeric columns (``N/A``, ``-1`` for an
    unknown rate), and a truncated capture can cut a field in half.
    """
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def airodump_to_evidences(
    raw_output: str,
    csv_content: Optional[str] = None,
    interface: Optional[str] = None,
    execution_id: Optional[str] = None,
    issues: Optional[List[str]] = None,
) -> List[Evidence]:
    """Convert airodump output to evidences.

    ``issues`` collects parsing problems so a caller can tell "the radio saw nothing"
    from "we could not read what the radio saw". Optional, so existing callers are
    unaffected.
    """
    evidences = []

    # Prefer CSV if available. When no CSV was supplied, raw_output is offered to the
    # CSV parser as a guess - callers that pass screen text there get the text fallback
    # below - so its complaints are only reported when CSV was actually declared.
    # ``is None`` rather than a truthiness test: an explicitly empty CSV is a declared
    # CSV that contained nothing, which is worth reporting, and passing raw_output to
    # the CSV parser instead would mislabel screen text as a malformed CSV section.
    csv_declared = csv_content is not None
    content_to_parse = csv_content if csv_declared else raw_output
    aps, clients = parse_airodump_csv(content_to_parse, issues=issues if csv_declared else None)

    # If CSV parsing failed, try text
    if not aps and not clients:
        if csv_declared:
            _note(
                issues,
                "airodump-ng CSV output yielded no usable AP or client rows; falling back to "
                "screen-output parsing, which is best-effort",
            )
        aps, clients = parse_airodump_text(raw_output, issues=issues)

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
