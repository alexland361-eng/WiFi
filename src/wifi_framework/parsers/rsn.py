"""Decode RSN (WPA2/WPA3) and RSNX information elements.

The byte decoder accepts an RSN element *body* (without the element-id and length
bytes). The text decoder accepts the human-readable ``iw dev wlan0 scan`` blocks. Keeping
both here avoids making the WPA3 posture model depend on Scapy or on a particular capture
format.

This parser only reports what is present. In particular, an absent RSNX H2E bit means
"not advertised", not "H2E is disabled", and SAE groups are not present in an RSN element
at all. They are negotiated later in SAE commit/confirm messages.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..core.models.wpa3 import (
    AKM_OUI,
    AKM_SUITE_NAMES,
    RSN_CAPAB_MFPC,
    RSN_CAPAB_MFPR,
    RSNX_CAPAB_PROTECTED_TWT,
    RSNX_CAPAB_SAE_H2E,
    RSNX_CAPAB_SAE_PK,
)


class RsnParseError(ValueError):
    """The bytes are not a structurally valid RSN element body."""


def _u16(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        raise RsnParseError("truncated 16-bit RSN field")
    return int.from_bytes(data[offset : offset + 2], "little")


def _suite(data: bytes, offset: int) -> Tuple[Tuple[int, int, int], int]:
    if offset + 4 > len(data):
        raise RsnParseError("truncated four-octet suite selector")
    return (tuple(data[offset : offset + 3]), data[offset + 3])  # type: ignore[return-value]


def _suites(data: bytes, offset: int, label: str) -> Tuple[List[int], int, List[Tuple[int, int, int]]]:
    count = _u16(data, offset)
    offset += 2
    types: List[int] = []
    ouis: List[Tuple[int, int, int]] = []
    if count > 128:
        raise RsnParseError(f"{label} suite count is implausibly large: {count}")
    for _ in range(count):
        oui, suite_type = _suite(data, offset)
        offset += 4
        ouis.append(oui)
        if oui == AKM_OUI:
            types.append(suite_type)
    return types, offset, ouis


def parse_rsn_ie(data: bytes) -> Dict[str, Any]:
    """Parse an RSN element body into security-relevant fields.

    Unknown OUIs are retained in ``*_suite_ouis`` while only standards-defined AKM types
    are returned in ``akm_suites``. This prevents a vendor selector from being mistaken for
    SAE or PSK merely because its final octet happens to be 8 or 2.
    """
    if not isinstance(data, bytes):
        raise TypeError("RSN element body must be bytes")
    if len(data) < 2:
        raise RsnParseError("RSN element is missing its version")
    version = _u16(data, 0)
    offset = 2
    group_oui, group_type = _suite(data, offset)
    offset += 4
    pairwise, offset, pairwise_ouis = _suites(data, offset, "pairwise")
    akm, offset, akm_ouis = _suites(data, offset, "AKM")

    result: Dict[str, Any] = {
        "version": version,
        "group_cipher_type": group_type if group_oui == AKM_OUI else None,
        "group_cipher_oui": group_oui,
        "pairwise_cipher_types": pairwise,
        "pairwise_cipher_ouis": pairwise_ouis,
        "akm_suites": akm,
        "akm_names": [AKM_SUITE_NAMES.get(value, f"unknown-{value}") for value in akm],
        "akm_suite_ouis": akm_ouis,
        "mfpc": None,
        "mfpr": None,
        "rsn_capabilities": None,
    }

    # RSN Capabilities and all following fields are optional in older RSN elements.
    if offset + 2 <= len(data):
        capabilities = _u16(data, offset)
        result["rsn_capabilities"] = capabilities
        result["mfpr"] = bool(capabilities & (1 << RSN_CAPAB_MFPR))
        result["mfpc"] = bool(capabilities & (1 << RSN_CAPAB_MFPC))
        offset += 2
    if offset < len(data):
        pmkid_count = _u16(data, offset)
        offset += 2 + (16 * pmkid_count)
        if offset > len(data):
            raise RsnParseError("truncated PMKID list")
    if offset < len(data):
        oui, cipher_type = _suite(data, offset)
        result["group_management_cipher_oui"] = oui
        result["group_management_cipher_type"] = cipher_type
        offset += 4
    if offset != len(data):
        raise RsnParseError("unexpected trailing bytes in RSN element")
    return result


def parse_rsn_ie_hex(value: str) -> Dict[str, Any]:
    """Parse whitespace/colon-separated hexadecimal RSN element body."""
    compact = re.sub(r"[\s:]", "", value or "")
    if not compact or len(compact) % 2 or re.fullmatch(r"[0-9A-Fa-f]+", compact) is None:
        raise RsnParseError("RSN hexadecimal input is not an even hexadecimal string")
    return parse_rsn_ie(bytes.fromhex(compact))


def parse_rsnx_ie(data: bytes) -> Dict[str, Any]:
    """Decode the RSNX capability octets (without element-id/length)."""
    if not isinstance(data, bytes):
        raise TypeError("RSNX element must be bytes")
    if not data:
        raise RsnParseError("empty RSNX element")
    bits = int.from_bytes(data, "little")
    return {
        "rsnx_capabilities": data,
        "sae_h2e": bool(bits & (1 << RSNX_CAPAB_SAE_H2E)),
        "sae_pk": bool(bits & (1 << RSNX_CAPAB_SAE_PK)),
        "protected_twt": bool(bits & (1 << RSNX_CAPAB_PROTECTED_TWT)),
    }


def _text_bool(line: str, true_words: Sequence[str]) -> Optional[bool]:
    lower = line.lower()
    if any(word in lower for word in true_words):
        return True
    if "not" in lower and any(word.replace("-", " ") in lower for word in true_words):
        return False
    return None


def parse_iw_rsn_lines(lines: Sequence[str]) -> Dict[str, Any]:
    """Parse the RSN/RSNX portions of one ``iw scan`` BSS block.

    ``iw`` output has changed wording between versions, so this deliberately recognizes
    only stable labels and leaves unknown values untouched in ``raw_rsn_lines``. It never
    treats a missing label as a negative observation.
    """
    result: Dict[str, Any] = {
        "akm_suites": [],
        "akm_names": [],
        "raw_rsn_lines": [],
        "mfpc": None,
        "mfpr": None,
        "h2e_advertised": None,
        "sae_pk_advertised": None,
    }
    in_rsn = False
    in_rsnx = False
    for raw in lines:
        stripped = raw.strip()
        lower = stripped.lower()
        if lower == "rsn:":
            in_rsn, in_rsnx = True, False
            continue
        if lower.startswith("rsnx") or lower.startswith("extended rsn"):
            in_rsn, in_rsnx = False, True
            continue
        if not stripped:
            continue
        # An unindented iw label starts the next BSS/property section.
        if (in_rsn or in_rsnx) and raw and not raw[0].isspace() and not lower.startswith("rsn"):
            in_rsn = in_rsnx = False
        if not (in_rsn or in_rsnx):
            continue
        if in_rsn:
            result["raw_rsn_lines"].append(stripped)
            match = re.search(r"authentication suites?:\s*(.*)$", stripped, re.I)
            if match:
                names = re.findall(r"[A-Za-z0-9][A-Za-z0-9+_.-]*", match.group(1))
                for name in names:
                    normalized = name.upper().replace("_", "-")
                    aliases = {
                        "SAE": 8,
                        "FT-SAE": 9,
                        "PSK": 2,
                        "FT-PSK": 4,
                        "OWE": 18,
                    }
                    if normalized in aliases and aliases[normalized] not in result["akm_suites"]:
                        result["akm_suites"].append(aliases[normalized])
                        result["akm_names"].append(AKM_SUITE_NAMES[aliases[normalized]])
            if "mfp-capable" in lower:
                result["mfpc"] = "not" not in lower
            if "mfp-required" in lower:
                result["mfpr"] = "not" not in lower
        else:
            if "sae h2e" in lower or "h2e" in lower:
                result["h2e_advertised"] = "not" not in lower
            if "sae pk" in lower:
                result["sae_pk_advertised"] = "not" not in lower
    return result
