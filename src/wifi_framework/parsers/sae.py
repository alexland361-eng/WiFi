"""Offline extraction of observed SAE negotiation facts from tshark output.

This parser does not generate SAE frames or infer group identifiers from arbitrary payload
bytes. It only accepts fields that tshark explicitly decoded as SAE/authentication fields.
That makes a missing dissector field an honest unknown instead of a fabricated group.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set


class SaeParseError(ValueError):
    """A structured capture result was malformed."""


def _walk_values(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield key, child
            yield from _walk_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_values(child)


def _integer(value: Any) -> Optional[int]:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"\d+", value.strip()):
        return int(value.strip())
    return None


def _packet_observation(layers: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    fields = list(_walk_values(layers))
    flat = {key.lower(): value for key, value in fields}

    algorithm = None
    sequence = None
    status = None
    group: Optional[int] = None
    for key, value in fields:
        lower = key.lower()
        if "auth_alg" in lower or lower.endswith("authentication.algorithm"):
            algorithm = _integer(value)
        elif "auth_seq" in lower or "authentication.sequence" in lower:
            sequence = _integer(value)
        elif "status_code" in lower and "wlan" in lower:
            status = _integer(value)
        # Names vary across Wireshark releases; accept only names explicitly identifying
        # an SAE/Dragonfly group, never a generic two-byte field.
        elif (
            ("sae" in lower or "dragonfly" in lower)
            and "group" in lower
        ):
            group = _integer(value)

    # Authentication algorithm 3 is SAE. If the dissector did not expose the algorithm,
    # an explicit SAE group field is still sufficient to establish that this is SAE data.
    if algorithm != 3 and group is None:
        return None
    result: Dict[str, Any] = {"sae": True}
    if algorithm is not None:
        result["authentication_algorithm"] = algorithm
    if sequence is not None:
        result["authentication_sequence"] = sequence
    if status is not None:
        result["status_code"] = status
    if group is not None:
        result["sae_group"] = group
    for key in ("wlan.sa", "wlan.ta", "wlan.da", "wlan.bssid"):
        if key in flat and isinstance(flat[key], str):
            result[key.rsplit(".", 1)[1]] = flat[key]
    return result


def parse_sae_tshark_json(output: str, issues: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Extract decoded SAE authentication observations from tshark JSON."""
    try:
        document = json.loads(output)
    except json.JSONDecodeError as exc:
        if issues is not None:
            issues.append(f"SAE tshark JSON could not be parsed: {exc.msg} at {exc.pos}")
        return []
    if not isinstance(document, list):
        if issues is not None:
            issues.append("SAE tshark JSON was not a packet list")
        return []

    observations: List[Dict[str, Any]] = []
    groups: Set[int] = set()
    for packet in document:
        if not isinstance(packet, dict):
            continue
        layers = packet.get("_source", {}).get("layers", {})
        if not isinstance(layers, dict):
            continue
        observation = _packet_observation(layers)
        if observation is None:
            continue
        if "sae_group" in observation:
            groups.add(observation["sae_group"])
        observations.append(observation)
    if observations:
        summary: Dict[str, Any] = {
            "sae": True,
            "sae_groups": sorted(groups),
            **({"bssid": observations[0]["bssid"]} if "bssid" in observations[0] else {}),
            "sae_observation_count": len(observations),
            "sae_commit_count": sum(item.get("authentication_sequence") == 1 for item in observations),
            "sae_confirm_count": sum(item.get("authentication_sequence") == 2 for item in observations),
            "observations": observations,
        }
        return [summary]
    if issues is not None:
        issues.append("capture contained no tshark-decoded SAE authentication observations")
    return []


def parse_sae_tshark_fields(
    output: str, columns: Sequence[str], issues: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """Extract SAE facts from tab-separated tshark fields with named columns."""
    required = {name.lower() for name in columns}
    if not any("auth_alg" in name or "sae" in name for name in required):
        if issues is not None:
            issues.append("SAE field extraction requires a named authentication or SAE column")
        return []
    observations: List[Dict[str, Any]] = []
    groups: Set[int] = set()
    for line in output.splitlines():
        if not line.strip():
            continue
        values = line.split("\t")
        if len(values) != len(columns):
            if issues is not None:
                issues.append("SAE field row did not match the requested column count")
            continue
        row = dict(zip((name.lower() for name in columns), values))
        algorithm = _integer(row.get("wlan.fixed.auth_alg"))
        group = None
        for key, value in row.items():
            if "sae" in key and "group" in key:
                group = _integer(value)
        if algorithm != 3 and group is None:
            continue
        item: Dict[str, Any] = {"sae": True}
        if algorithm is not None:
            item["authentication_algorithm"] = algorithm
        sequence = _integer(row.get("wlan.fixed.auth_seq"))
        if sequence is not None:
            item["authentication_sequence"] = sequence
        if group is not None:
            item["sae_group"] = group
            groups.add(group)
        for key in ("wlan.bssid", "wlan.sa", "wlan.da"):
            if key in row and row[key].strip():
                item[key.rsplit(".", 1)[1]] = row[key].strip()
        observations.append(item)
    if not observations and issues is not None:
        issues.append("field output contained no explicit SAE observations")
    if not observations:
        return []
    return [{
        "sae": True,
        **({"bssid": observations[0]["bssid"]} if "bssid" in observations[0] else {}),
        "sae_groups": sorted(groups),
        "sae_observation_count": len(observations),
        "sae_commit_count": sum(item.get("authentication_sequence") == 1 for item in observations),
        "sae_confirm_count": sum(item.get("authentication_sequence") == 2 for item in observations),
        "observations": observations,
    }]
