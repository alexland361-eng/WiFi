"""Parse the WPA3-relevant subset of hostapd/wpa_supplicant configuration.

This is an audit parser, not a configuration writer. It never returns passwords or
``sae_password`` values. Unknown keys are ignored; malformed security values are reported
in ``issues`` and left unknown rather than coerced into a safe-looking posture.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from ..core.models.wpa3 import Wpa3Posture


def _values(settings: Dict[str, str], key: str) -> List[str]:
    return settings.get(key, "").split()


_SECRET_KEYS = {"wpa_passphrase", "sae_password", "psk", "password"}


def sanitize_wpa_config(text: str) -> str:
    """Remove secret values before configuration text enters an evidence record."""
    safe_lines: List[str] = []
    for raw in text.splitlines():
        if "=" not in raw:
            safe_lines.append(raw)
            continue
        key, _value = (part.strip() for part in raw.split("=", 1))
        if key in _SECRET_KEYS:
            safe_lines.append(f"{key}=<redacted>")
        else:
            safe_lines.append(raw)
    return "\n".join(safe_lines)


def parse_wpa_config(
    text: str,
    *,
    bssid: str = "",
    version: Optional[str] = None,
    source: str = "config",
    issues: Optional[List[str]] = None,
) -> Wpa3Posture:
    """Build a WPA3 posture from a hostapd or wpa_supplicant config fragment.

    A config may contain multiple ``network={}`` blocks. This small audit parser reads the
    supplied fragment as one selected scope; when given a whole multi-network file, later
    occurrences of a key replace earlier ones. Callers auditing a supplicant should pass
    one selected network block at a time.
    """
    settings: Dict[str, str] = {}
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = line.split("#", 1)[0].strip()
        if "=" not in line:
            if issues is not None:
                issues.append(f"config line {line_number} has no key=value delimiter")
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if not key:
            if issues is not None:
                issues.append(f"config line {line_number} has an empty key")
            continue
        # Do not retain secrets, even transiently in the posture.
        if key in {"wpa_passphrase", "sae_password", "psk", "password"}:
            continue
        settings[key] = value

    akm: List[int] = []
    for token in _values(settings, "wpa_key_mgmt"):
        normalized = token.upper().replace("_", "-")
        mapping = {
            "SAE": 8,
            "FT-SAE": 9,
            "WPA-PSK": 2,
            "WPA-PSK-SHA256": 6,
            "FT-PSK": 4,
            "WPA-EAP": 1,
            "WPA-EAP-SHA256": 5,
            "FT-EAP": 3,
            "OWE": 18,
        }
        if normalized in mapping and mapping[normalized] not in akm:
            akm.append(mapping[normalized])
        elif normalized not in mapping and issues is not None:
            issues.append(f"unrecognized wpa_key_mgmt value {token!r}")

    groups: Optional[List[int]] = None
    if "sae_groups" in settings:
        groups = []
        for token in _values(settings, "sae_groups"):
            if re.fullmatch(r"\d+", token):
                groups.append(int(token))
            elif issues is not None:
                issues.append(f"invalid sae_groups token {token!r}")

    sae_pwe: Optional[int] = None
    if "sae_pwe" in settings:
        if re.fullmatch(r"\d+", settings["sae_pwe"]):
            sae_pwe = int(settings["sae_pwe"])
        elif issues is not None:
            issues.append(f"invalid sae_pwe value {settings['sae_pwe']!r}")

    mfp: Optional[int] = None
    if "ieee80211w" in settings and re.fullmatch(r"[012]", settings["ieee80211w"]):
        mfp = int(settings["ieee80211w"])
    elif "ieee80211w" in settings and issues is not None:
        issues.append(f"invalid ieee80211w value {settings['ieee80211w']!r}")
    if settings.get("sae_require_mfp") == "1":
        mfp = 2

    threshold: Optional[int] = None
    if "anti_clogging_threshold" in settings:
        if re.fullmatch(r"\d+", settings["anti_clogging_threshold"]):
            threshold = int(settings["anti_clogging_threshold"])
        elif issues is not None:
            issues.append("invalid anti_clogging_threshold value")

    eap_pwd_configured: Optional[bool] = None
    if settings.get("eap", "").upper() == "PWD" or "eap_pwd_groups" in settings:
        eap_pwd_configured = True

    return Wpa3Posture(
        bssid=bssid,
        akm_suites=akm,
        mfpc=(mfp is not None and mfp > 0) if mfp is not None else None,
        mfpr=(mfp == 2) if mfp is not None else None,
        sae_groups=groups,
        sae_pwe=sae_pwe,
        anti_clogging_threshold=threshold,
        transition_disable_configured=(settings.get("transition_disable") == "1")
        if "transition_disable" in settings
        else None,
        eap_pwd_configured=eap_pwd_configured,
        version=version,
        source=source,
    )
