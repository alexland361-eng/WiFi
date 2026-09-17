"""
Base parser utilities.
"""
from __future__ import annotations

import re
from typing import Dict, List


def extract_macs(text: str) -> List[str]:
    """Extract MAC addresses from text."""
    mac_pattern = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
    return mac_pattern.findall(text)


def extract_ips(text: str) -> List[str]:
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    return ip_pattern.findall(text)


def parse_key_value_output(output: str, delimiter: str = ":") -> Dict[str, str]:
    """Parse simple key: value output."""
    result = {}
    for line in output.splitlines():
        if delimiter in line:
            parts = line.split(delimiter, 1)
            key = parts[0].strip().lower().replace(" ", "_")
            value = parts[1].strip()
            if key and value:
                result[key] = value
    return result
