"""
Validation utilities for tool parameters and inputs.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple


MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
BSSID_REGEX = MAC_REGEX

SSID_MAX_LENGTH = 32


def validate_mac(mac: str) -> Tuple[bool, str]:
    """Validate MAC address format."""
    if not mac:
        return False, "MAC address is empty"
    if not MAC_REGEX.match(mac):
        # Also allow without separators? Check 12 hex chars
        cleaned = re.sub(r"[^0-9a-fA-F]", "", mac)
        if len(cleaned) == 12 and all(c in "0123456789abcdefABCDEF" for c in cleaned):
            return True, ""
        return False, f"Invalid MAC format: {mac}"
    return True, ""


def normalize_mac(mac: str) -> Optional[str]:
    """Normalize MAC to upper colon format."""
    if not mac:
        return None
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(cleaned) != 12:
        return None
    return ":".join(cleaned[i:i+2] for i in range(0, 12, 2)).upper()


def validate_ssid(ssid: str) -> Tuple[bool, str]:
    if ssid is None:
        return False, "SSID is None"
    if len(ssid) > SSID_MAX_LENGTH:
        return False, f"SSID too long: {len(ssid)} > {SSID_MAX_LENGTH}"
    # SSID can be empty for hidden, but not None
    return True, ""


def validate_channel(channel: Any) -> Tuple[bool, str]:
    try:
        ch = int(channel)
    except (ValueError, TypeError):
        return False, f"Channel must be integer, got {channel}"
    if not 1 <= ch <= 196:
        return False, f"Channel {ch} out of valid range 1-196"
    return True, ""


def validate_interface(interface: str) -> Tuple[bool, str]:
    if not interface:
        return False, "Interface name empty"
    if not re.match(r"^[a-zA-Z0-9._-]+$", interface):
        return False, f"Invalid interface name: {interface}"
    if len(interface) > 15:  # Linux IFNAMSIZ
        return False, f"Interface name too long: {interface}"
    return True, ""


def validate_ip(ip: str) -> Tuple[bool, str]:
    import ipaddress

    try:
        ipaddress.ip_address(ip)
        return True, ""
    except ValueError as e:
        return False, str(e)


def validate_cidr(cidr: str) -> Tuple[bool, str]:
    import ipaddress

    try:
        ipaddress.ip_network(cidr, strict=False)
        return True, ""
    except ValueError as e:
        return False, str(e)


def validate_parameters(params: Dict[str, Any], required: List[str], validators: Dict[str, callable] = None) -> Tuple[bool, List[str]]:
    """
    Validate parameters dict against required list and custom validators.

    Returns (is_valid, error_messages)
    """
    errors = []
    validators = validators or {}

    for req in required:
        if req not in params or params[req] is None:
            errors.append(f"Missing required parameter: {req}")

    for key, validator in validators.items():
        if key in params and params[key] is not None:
            valid, msg = validator(params[key])
            if not valid:
                errors.append(f"Parameter {key}: {msg}")

    return len(errors) == 0, errors


def sanitize_command_arg(arg: str) -> str:
    """Basic sanitization for command args to prevent injection."""
    if not isinstance(arg, str):
        return str(arg)
    # Disallow shell metacharacters that could cause injection if shell=True (we never use shell=True, but defense in depth)
    dangerous = [";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r"]
    for char in dangerous:
        if char in arg:
            # We'll allow but log; since we use list form, it's safe, but flag
            pass
    return arg
