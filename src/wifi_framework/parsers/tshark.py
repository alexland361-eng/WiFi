"""
Parser for tshark output.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ..core.models.evidence import ConfidenceLevel, Evidence, EvidenceType


def parse_tshark_json(output: str, issues: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Parse tshark -T json output.

    ``issues``, when given, receives a description of any extraction problem. tshark
    is stopped by a timeout or a capture filter mid-write often enough that truncated
    JSON is a normal outcome, and a truncated document parses to nothing - which
    reads as "no packets captured" unless the failure is declared.
    """
    results = []
    try:
        data = json.loads(output)
        if isinstance(data, list):
            for packet in data:
                # Extract relevant layers
                layers = packet.get("_source", {}).get("layers", {})
                entry = {
                    "layers": list(layers.keys()),
                    "raw": layers,
                }
                # Try to extract common fields
                if "wlan" in layers:
                    wlan = layers["wlan"]
                    if isinstance(wlan, dict):
                        entry["bssid"] = wlan.get("wlan.bssid") or wlan.get("wlan.da")
                        entry["ssid"] = wlan.get("wlan_mgt.ssid")
                results.append(entry)
    except json.JSONDecodeError as exc:
        if issues is not None:
            issues.append(
                f"tshark JSON output could not be parsed ({exc.msg} at position {exc.pos}); "
                "the empty result means the output was unusable or truncated, not that no "
                "packets were captured"
            )
    return results


def parse_tshark_fields(output: str) -> List[Dict[str, Any]]:
    """Parse tshark -T fields output."""
    results = []
    for line in output.splitlines():
        if not line.strip():
            continue
        # Assume tab-separated fields
        parts = line.split("\t")
        entry = {"fields": parts, "raw_line": line}
        results.append(entry)
    return results


def tshark_to_evidences(
    output: str,
    interface: Optional[str] = None,
    execution_id: Optional[str] = None,
    issues: Optional[List[str]] = None,
) -> List[Evidence]:
    """Convert tshark output to evidences.

    ``issues`` collects extraction problems for the caller to report; see
    :func:`parse_tshark_json`.
    """
    evidences = []
    # Try JSON first
    if output.strip().startswith("[") or output.strip().startswith("{"):
        parsed = parse_tshark_json(output, issues=issues)
        for entry in parsed:
            ev = Evidence.from_tool_output(
                tool_name="tshark",
                capability="packet_capture",
                evidence_type=EvidenceType.CAPTURE,
                raw_output=output,
                parsed_data=entry,
                parameters={"interface": interface} if interface else {},
                interface=interface,
                confidence=ConfidenceLevel.MEDIUM,
                execution_id=execution_id,
                raw_command="tshark",
            )
            evidences.append(ev)
    else:
        parsed = parse_tshark_fields(output)
        for entry in parsed:
            ev = Evidence.from_tool_output(
                tool_name="tshark",
                capability="packet_capture",
                evidence_type=EvidenceType.CAPTURE,
                raw_output=output,
                parsed_data=entry,
                parameters={"interface": interface} if interface else {},
                interface=interface,
                confidence=ConfidenceLevel.LOW,
                execution_id=execution_id,
                raw_command="tshark",
            )
            evidences.append(ev)

    # If no structured parsing succeeded, still create generic evidence
    if not evidences and output.strip():
        ev = Evidence.from_tool_output(
            tool_name="tshark",
            capability="packet_capture",
            evidence_type=EvidenceType.CAPTURE,
            raw_output=output,
            parsed_data={"raw": output[:1000]},
            parameters={},
            interface=interface,
            confidence=ConfidenceLevel.LOW,
            execution_id=execution_id,
            raw_command="tshark",
        )
        evidences.append(ev)

    return evidences
