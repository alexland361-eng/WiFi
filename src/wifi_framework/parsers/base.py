"""
Base parser utilities: pulling addresses and key/value pairs out of unstructured text.

What counts as a MAC address, and what counts as an IP address, is decided by
:mod:`wifi_framework.utils.validation` and nowhere else. That is not a stylistic preference.
An address a parser extracts and an address an operator authorizes are compared against each
other later - by the scope checks that decide what may be attacked - so two rules that
disagree produce either a refusal against an asset the operator named, or a match against one
they did not. :func:`~wifi_framework.utils.validation.normalize_mac` exists because an
earlier version of it stripped non-hex characters and so turned ``AABBCCDDEEFFGG`` into a
*different* address, silently authorizing a network nobody had named. These helpers find
candidates in text and then ask that function whether each candidate is real.

No production parser calls these today: each has extraction tuned to its own tool's output
format, and :func:`wifi_framework.parsers.airodump.parse_airodump_csv` is the authoritative
wireless parser. They are exercised by ``scripts/exercise_framework.py``, and they stay
because "pull every address out of this blob" is a recurring need when a tool's format is
unknown or has changed - which is precisely the situation where a hand-rolled regex diverges
from the rule the rest of the framework uses.
"""
from __future__ import annotations

import re
from typing import Dict, List

from ..utils.validation import normalize_mac, validate_ip

#: A run that could be a MAC address, in colon or dash form.
#:
#: The boundaries are the point. Without them a longer token contributes part of itself:
#: ``00:11:22:33:44:55:66`` is eight groups and not an address, yet the unbounded pattern
#: extracts ``00:11:22:33:44:55`` from it and reports an address that is not in the text.
#: ``AABBCCDDEEFFGG`` yields ``AABBCCDDEEFF`` the same way - the exact transformation
#: :func:`normalize_mac` was written to refuse. The class is alphanumeric rather than
#: hex-only so that a neighbouring letter ends the token even when that letter is not a hex
#: digit. The separators are permissive on purpose: a mixed ``AA:BB-CC:DD-EE:FF`` is found
#: here and then correctly refused by the canonical rule, which is the division of labour -
#: this pattern locates candidates, ``normalize_mac`` decides.
#:
#: The bare twelve-hex-digit form is deliberately **not** a candidate here, although
#: :func:`normalize_mac` accepts it. In free text a bare run of twelve digits is far more
#: likely to be a number than an address: ``202401011200`` is a timestamp, and extracting
#: ``20:24:01:01:12:00`` from it invents an access point. Tool output is full of such
#: numbers. The separated forms carry their own evidence of intent; a bare run does not.
#: :func:`wifi_framework.parsers.wash.parse_wash` does accept the bare form, because there
#: the value is the first field of a row under a column the tool labelled ``BSSID`` - the
#: position means something that a blob of text cannot. Same canonical rule, different
#: evidence available at the call site.
_MAC_CANDIDATE = re.compile(
    r"(?<![0-9A-Za-z:\-.])"
    r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"
    r"(?![0-9A-Za-z:\-.])"
)

#: A run that could be a dotted-quad. Bounded for the same reason: ``1.2.3.4.5.6.7.8`` is
#: not two addresses, and without the lookahead and lookbehind the unbounded pattern reports
#: ``1.2.3.4`` and ``5.6.7.8`` from it. Whether a candidate is an address at all is decided
#: by :func:`~wifi_framework.utils.validation.validate_ip`, so ``999.999.999.999`` is found
#: here and refused there rather than being accepted because it has the right shape.
_IP_CANDIDATE = re.compile(
    r"(?<![0-9A-Za-z_\-.:])"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"(?![0-9A-Za-z_\-.:])"
)


def extract_macs(text: str) -> List[str]:
    """Extract MAC addresses from text, in canonical upper colon form.

    Every value returned is one :func:`~wifi_framework.utils.validation.normalize_mac`
    accepts, so a lowercase ``aa:bb:cc:dd:ee:ff`` comes back as ``AA:BB:CC:DD:EE:FF`` and a
    dash-separated form comes back colon-separated. A candidate that is not an address -
    mixed separators, trailing garbage, a longer run of groups - is dropped rather than
    partially matched.

    Only separated forms are found. A bare ``AABBCCDDEEFF`` is a valid MAC to
    :func:`normalize_mac` but is not extracted from text, where twelve digits in a row are
    more often a timestamp or a counter; see :data:`_MAC_CANDIDATE`.

    Occurrences are returned in the order found and duplicates are kept: the same address
    appearing twice in a frame is two observations of it, and collapsing them is the
    caller's decision, not this function's.
    """
    found: List[str] = []
    for match in _MAC_CANDIDATE.finditer(text):
        normalized = normalize_mac(match.group(0))
        if normalized is not None:
            found.append(normalized)
    return found


def extract_ips(text: str) -> List[str]:
    """Extract IPv4 addresses from text.

    **IPv4 only.** An IPv6 address is not found by this function, and it is not reported as
    an error either, so a caller working with a dual-stack scope must not treat an empty
    result as "no addresses here". Extracting IPv6 from arbitrary text is not a regex
    problem - colon-separated hex runs collide with MAC addresses, timestamps and frame
    numbers - and guessing at it would produce addresses that were never in the input.

    Each candidate is confirmed by :func:`~wifi_framework.utils.validation.validate_ip`,
    which is :func:`ipaddress.ip_address` under the hood, so octet ranges and leading zeros
    are judged by the standard library rather than by ``\\d{1,3}``.
    """
    found: List[str] = []
    for match in _IP_CANDIDATE.finditer(text):
        candidate = match.group(0)
        valid, _reason = validate_ip(candidate)
        if valid:
            found.append(candidate)
    return found


def parse_key_value_output(output: str, delimiter: str = ":") -> Dict[str, str]:
    """Parse simple ``key: value`` output into a dict.

    Keys are lowercased with their spaces replaced by underscores, so ``"Signal level"`` is
    stored as ``signal_level`` and looking up the literal key finds nothing. Where a key
    occurs more than once, the last occurrence wins. A line with no delimiter, or with
    nothing but whitespace before it, is not a key/value pair and is skipped.

    A key with an *empty* value is kept. The ``if key and value`` guard this replaces dropped
    it, which discards something the parser did see - and in this domain the empty value is
    often the interesting case: ``ESSID:`` with nothing after it is a hidden network, not a
    missing field.
    """
    result: Dict[str, str] = {}
    for line in output.splitlines():
        if delimiter not in line:
            continue
        key_part, _, value_part = line.partition(delimiter)
        key = key_part.strip().lower().replace(" ", "_")
        if not key:
            continue
        result[key] = value_part.strip()
    return result
