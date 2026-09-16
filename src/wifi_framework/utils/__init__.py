from .system import (
    check_interface_exists,
    check_tool_available,
    get_interface_list,
    get_os_info,
    is_root,
    run_command,
)
from .validation import (
    normalize_mac,
    validate_channel,
    validate_interface,
    validate_ip,
    validate_mac,
    validate_parameters,
    validate_ssid,
)


def validate_bssid(bssid: str):
    return validate_mac(bssid)

__all__ = [
    "get_os_info",
    "is_root",
    "check_tool_available",
    "check_interface_exists",
    "get_interface_list",
    "run_command",
    "validate_mac",
    "validate_bssid",
    "normalize_mac",
    "validate_ssid",
    "validate_channel",
    "validate_interface",
    "validate_ip",
    "validate_parameters",
]
