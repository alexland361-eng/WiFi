"""
Parser for wash - WPS discovery tool.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..core.models.evidence import ConfidenceLevel, Evidence, EvidenceType
from ..utils.validation import normalize_mac

#: A wash data row: BSSID, channel, dBm, WPS version, lock flag, vendor, ESSID.
#:
#: The first group is deliberately permissive - 17 characters of hex-or-colon - because
#: deciding *whether a line is a row* and deciding *whether a field is an address* are
#: different questions. This pattern answers the first; :func:`normalize_mac` answers the
#: second. Seventeen hex-or-colon characters include strings that are not addresses at all
#: (``:::::::::::::::::``, or a bare 17-character hex run), and those are reported rather
#: than recorded - see :func:`parse_wash`.
_WASH_ROW = re.compile(
    r"^\s*([0-9A-Fa-f:]{17})\s+(\d+)\s+(-?\d+)\s+([\d\.]+|n/a)\s+(\w+)\s+(\S+)?\s*(.*)?$"
)

#: A field that looks like it was *meant* to be an address. Used only by the fallback branch,
#: to decide whether an unrecognized line is worth reporting: a malformed BSSID is, and a line
#: of wash's own banner text ("Scanning for WPS enabled access points...") is not. Reporting
#: every unrecognized line would fill ``parse_warnings`` with prose and bury the rows that
#: actually failed to parse, which is the opposite of why the list exists.
#:
#: The class admits any alphanumeric, not just hex, and the length rather than the first
#: character does the discriminating. Both matter: the case most in need of a report is a
#: near miss like ``AA:BB:CC:DD:EE:FFGG``, whose trailing ``G`` is not a hex digit, and a
#: hex-only class would classify it as prose and drop it silently - the defect this whole
#: channel exists to remove. Twelve characters is below any separated address (17) and above
#: the words wash prints around its rows.
_ADDRESS_SHAPED = re.compile(r"\A[0-9A-Za-z:\-.]{12,}\Z")


def parse_wash(output: str, issues: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """
    Parse wash output.

    Example:
    BSSID              Ch  dBm  WPS  Lck  Vendor    ESSID
    00:11:22:33:44:55  6   -45  2.0  No   Broadcom  MyNetwork

    ``issues`` is an optional list the caller passes to learn what the parser could not use,
    the same convention as :func:`~wifi_framework.parsers.nmap.parse_nmap_xml` and
    :func:`~wifi_framework.parsers.tshark.parse_tshark_json`. :class:`WashAdapter` forwards
    it to ``parse_warnings``, which reaches ``ExecutionResult`` and the evidence engine, so a
    row that failed to parse is visible instead of simply absent from the results.

    Every BSSID goes through :func:`~wifi_framework.utils.validation.normalize_mac`, which is
    the framework's single answer to "is this a MAC address" - the same rule an operator's
    scope allowlist is normalized with, so a parsed address and an authorized address cannot
    disagree about what counts. Before that, the row pattern's 17-character field was taken as
    an address unchanged, so ``:::::::::::::::::`` was recorded as a BSSID; and the fallback
    branch used an unanchored ``re.match``, so ``AA:BB:CC:DD:EE:FFGG`` was recorded with its
    trailing garbage attached. A BSSID identifies what may be attacked, so a value the
    canonical rule rejects must not enter the world model. The same rule accepts the dash
    form, which the old colon-only ``re.match`` discarded without a word - an address wash
    really did report, going missing from the results.

    It also accepts a bare twelve-hex-digit form, and the fallback branch still refuses that
    one. A line this parser could not structure is the least trustworthy place in the
    document, and the adapter hands it stdout and stderr together; the comment there gives
    the reasoning. The main branch is unaffected, its pattern requiring separators already.
    """
    results: List[Dict[str, Any]] = []
    reported: List[str] = issues if issues is not None else []

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

        m = _WASH_ROW.match(line)
        if m:
            token = m.group(1)
            bssid = normalize_mac(token)
            if bssid is None:
                # The line carries every column of a wash row, so it was meant to be data.
                # Its first field is not an address, and recording it would put an
                # identifier into the world model that no scope entry can ever match.
                reported.append(f"wash: row for {token!r} skipped: not a MAC address")
                continue
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
            # Fallback: a line the column pattern did not match. ``line`` is known to be
            # non-blank - blank lines are skipped above - so ``parts`` is never empty.
            #
            # The first field is normalized rather than pattern-matched. The old
            # ``re.match`` was colon-only and unanchored, which discarded the dash and bare
            # forms without a word and accepted ``AA:BB:CC:DD:EE:FFGG`` with its trailing
            # garbage attached.
            #
            # This path requires a *separated* address, unlike :func:`normalize_mac`, which
            # also accepts a bare twelve-hex-digit form. The reason is what reaches this
            # branch: the adapter parses ``raw_output + error_output`` as one document, so
            # once the header has been seen, wash's stderr is parsed too. A bare run of
            # twelve digits there is likelier to be a timestamp or a counter than an address,
            # and recording it would invent an access point. A colon or a dash is evidence of
            # intent that a bare run does not carry. The main branch needs no such guard -
            # its pattern already requires the separators.
            parts = line.split()
            token = parts[0]
            bssid = normalize_mac(token) if (":" in token or "-" in token) else None
            if bssid is None:
                # Only report a field that looks like an address. wash prints banner text
                # between the header and the rows, and reporting prose would bury the
                # malformed rows this list exists to surface.
                if _ADDRESS_SHAPED.match(token):
                    # Say which refusal this was. "Not an address" and "an address, but only
                    # in a form this unstructured line does not establish" send an operator
                    # looking in different directions - the first at a corrupt capture, the
                    # second at a tool emitting a format this parser does not expect.
                    reason = (
                        "not a MAC address"
                        if normalize_mac(token) is None
                        else "a MAC address only in bare form, which this line does not establish"
                    )
                    reported.append(
                        f"wash: line {line.strip()!r} skipped: first field {token!r} is {reason}"
                    )
                continue
            results.append(
                {
                    "bssid": bssid,
                    "raw_line": line.strip(),
                    "wps_enabled": True,  # If listed by wash, WPS is present
                }
            )

    return results


def wash_to_evidences(
    output: str,
    interface: Optional[str] = None,
    execution_id: Optional[str] = None,
    issues: Optional[List[str]] = None,
) -> List[Evidence]:
    """Build WPS evidences from wash output.

    ``issues`` is passed through to :func:`parse_wash` so a caller can learn which lines
    could not be parsed. Without it the evidence list is all the caller sees, and a row
    wash reported but this parser could not use is indistinguishable from a row wash never
    saw.
    """
    evidences = []
    parsed = parse_wash(output, issues)
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
