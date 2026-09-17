"""
Validation utilities for tool parameters and inputs.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Tuple


#: The three exact spellings of a MAC address that this framework accepts.
#:
#: All are anchored with ``\A``/``\Z`` rather than ``^``/``$``, because in Python ``$`` also matches
#: immediately *before a trailing newline*. For :func:`validate_interface` - which does not strip -
#: that is the actual fix: ``"wlan0\n"`` used to pass.
#:
#: For MACs the anchoring is hygiene rather than a behaviour change: :func:`normalize_mac` strips
#: surrounding whitespace *first*, so ``"AA:BB:CC:DD:EE:FF\n"`` is still accepted, deliberately.
#: Whitespace cannot change which address a value denotes, so removing it is safe - unlike removing
#: arbitrary non-hex characters, which is what used to turn malformed input into a different
#: address. ``\Z`` keeps the pattern honest about what it matches on its own.
MAC_REGEX = re.compile(r"\A([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\Z")
BSSID_REGEX = MAC_REGEX
_MAC_DASH_REGEX = re.compile(r"\A([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\Z")
_MAC_BARE_REGEX = re.compile(r"\A[0-9A-Fa-f]{12}\Z")

SSID_MAX_LENGTH = 32


def normalize_mac(mac: str) -> Optional[str]:
    """
    Normalize a MAC/BSSID to upper colon form, or return ``None`` if it is not one.

    Only surrounding whitespace and the two separator characters are removed, because neither can
    change *which* address the value denotes. Everything else is rejected outright.

    That distinction is the whole point of this function. The previous implementation stripped every
    non-hex character with ``re.sub(r"[^0-9a-fA-F]", "", mac)``, so ``"AABBCCDDEEFFGG"`` was
    silently "cleaned" into ``AA:BB:CC:DD:EE:FF`` - a *different* address from the one written.
    Where the input is an operator's scope allowlist, that quietly authorises a network nobody named
    while ``AssessmentScope.validate()`` reports no error. Refusing malformed input is the only
    safe behaviour for an identifier that decides what may be attacked.
    """
    if not mac or not isinstance(mac, str):
        return None
    candidate = mac.strip()
    if not (
        MAC_REGEX.match(candidate)
        or _MAC_DASH_REGEX.match(candidate)
        or _MAC_BARE_REGEX.match(candidate)
    ):
        return None
    digits = candidate.replace(":", "").replace("-", "")
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).upper()


def validate_mac(mac: str) -> Tuple[bool, str]:
    """
    Validate MAC address format.

    Delegates to :func:`normalize_mac` so that "is this a MAC" has exactly one answer in the
    codebase; the two functions previously disagreed about which malformed inputs were acceptable.
    """
    if not mac:
        return False, "MAC address is empty"
    if normalize_mac(mac) is None:
        return False, f"Invalid MAC format: {mac}"
    return True, ""


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


#: Anchored with ``\Z``: ``$`` would also match before a trailing newline, which is how
#: ``"wlan0\n"`` used to pass. A name carrying a newline is not an interface, and it reaches
#: ``/sys/class/net/<name>`` path construction and tool argv.
_INTERFACE_REGEX = re.compile(r"\A[a-zA-Z0-9._-]+\Z")


def validate_interface(interface: str) -> Tuple[bool, str]:
    """
    Validate a network interface name.

    The name is interpolated into ``/sys/class/net/{interface}`` and passed to tools, so ``.`` and
    ``..`` are refused even though they match the character class: ``/sys/class/net/..`` exists, so
    a traversal value would be reported as a present interface.
    """
    if not interface:
        return False, "Interface name empty"
    if not isinstance(interface, str):
        return False, f"Invalid interface name: {interface!r}"
    if not _INTERFACE_REGEX.match(interface):
        return False, f"Invalid interface name: {interface}"
    # ``eth0.100`` is a legitimate VLAN name, so dots are allowed - but an empty segment means the
    # name is made only of dots (``.``, ``..``) or has a stray leading/trailing one. Refusing those
    # closes the traversal: ``/sys/class/net/..`` exists, so it would otherwise be reported as a
    # present interface. ``/`` is already excluded by the character class above.
    if any(segment == "" for segment in interface.split(".")):
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


def integral_int(value: Any) -> Optional[int]:
    """A whole number from ``value``, or ``None`` if it is not one.

    Refuses rather than truncates, because ``int(6.5)`` is 6 and a silently rounded
    channel is a wrong channel - for an access point that means observations attributed
    to a frequency it is not on. Integral strings and floats are accepted: a tool
    printing ``"-45.0"`` for a signal level has said something unambiguous. ``nan`` and
    ``inf`` are refused, which ``float.is_integer`` settles without a separate guard.

    This is deliberately *not* the rule ``validate_channel`` and the policy scope gate
    use. Those two coerce with ``int()`` and are coupled to each other by tests in
    ``test_policy.py`` - the gate skips a value it cannot coerce and parameter validation
    refuses it, so both must convert identically or a channel slips past both. This
    helper is the stricter rule for values being *recorded*: a declared channel in an
    authorization scope, or an observed channel written into the world model, where a
    rounded number becomes a stored fact rather than a one-off comparison.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    if not number.is_integer():
        return None
    return int(number)


def validate_parameters(params: Dict[str, Any], required: List[str], validators: Optional[Dict[str, Callable[[Any], Tuple[bool, str]]]] = None) -> Tuple[bool, List[str]]:
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



# ---------------------------------------------------------------------------------------------
# Characters that must never appear in a value handed to a tool.
#
# These are the single definition; ``ActionPolicy`` imports them and turns a match into a
# non-retriable rejection (issue codes ``control_character`` and ``shell_metacharacter``).
#
# The framework *rejects* rather than rewrites. Every command reaches ``subprocess.run`` as an argv
# list and is never interpreted by a shell, so there is nothing to escape - and rewriting would be
# actively dangerous: an SSID legitimately contains ``$`` or ``&``, and silently mutating it would
# aim the assessment at a network the operator never authorised. Refusing is honest; sanitising a
# target identifier is not.
#
# There is deliberately no ``sanitize_command_arg`` helper. A function by that name shipped in
# 0.1.0, iterated over these characters and discarded the result, and returned its input unchanged.
# It was never called, but its presence let four documents claim a sanitisation control that did not
# exist. Removed in 0.4.0; the real control is the policy rejection described above.
# ---------------------------------------------------------------------------------------------

#: Control characters: no tool argument has a legitimate reason to contain these.
CONTROL_CHARS: Tuple[str, ...] = ("\n", "\r", "\x00")

#: Shell metacharacters: inert in an argv list, but their presence in a wireless parameter means
#: the value did not come from observed state, so the action is refused.
SHELL_METACHARACTERS: Tuple[str, ...] = (";", "&", "|", "`", "$(", ">", "<")
