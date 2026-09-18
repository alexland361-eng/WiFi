"""Parse non-secret wpa_cli connection status into WPA3 posture."""
from __future__ import annotations

from typing import Dict, List, Optional

from ..core.models.wpa3 import Wpa3Posture
from ..utils.validation import normalize_mac
from .wpa_config import parse_wpa_config


def parse_wpa_cli_status(
    text: str, *, interface: Optional[str] = None, issues: Optional[List[str]] = None
) -> Wpa3Posture:
    """Parse ``wpa_cli status`` without retaining credential material.

    This observes the group/PWE selected for the current connection. It does not establish
    what every AP client would negotiate, and it does not transmit or reconnect.
    """
    values: Dict[str, str] = {}
    for line_number, raw in enumerate(text.splitlines(), 1):
        if "=" not in raw:
            continue
        key, value = (part.strip() for part in raw.split("=", 1))
        if key in {"psk", "password", "passphrase"}:
            continue
        values[key] = value

    bssid = normalize_mac(values.get("bssid", "")) or ""
    key_mgmt = values.get("key_mgmt", "")
    config_lines = [f"wpa_key_mgmt={key_mgmt}"] if key_mgmt else []
    if "sae_group" in values:
        config_lines.append(f"sae_groups={values['sae_group']}")
    if "sae_pwe" in values:
        config_lines.append(f"sae_pwe={values['sae_pwe']}")
    posture = parse_wpa_config(
        "\n".join(config_lines), bssid=bssid, source="wpa_cli status", issues=issues
    )
    posture.ssid = values.get("ssid")
    if interface:
        posture.source = f"wpa_cli status:{interface}"
    return posture
