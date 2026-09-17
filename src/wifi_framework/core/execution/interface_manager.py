"""
Interface Manager - Advanced wireless interface handling and management.

Handles:
- Monitor mode creation and teardown (airmon-ng, iw)
- Channel setting and hopping
- MAC address management (macchanger)
- Interface up/down
- Driver and chipset detection
- Capability verification (monitor, injection)

Deep research confirmation: Real usage of airmon-ng, iw, macchanger, etc.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from ...utils.system import check_interface_exists, effective_capabilities, run_command
from ...utils.validation import validate_mac, normalize_mac
from ..models.assessment_state import InterfaceInfo
from .tool_manager import ToolManager


def _can_admin_interfaces(tool_manager: Any) -> bool:
    """Whether this process may bring interfaces up/down and switch their type.

    Those operations require CAP_NET_ADMIN, not a root uid. Gating on ``is_root``
    meant an unprivileged process holding CAP_NET_ADMIN - a normal way to run a
    wireless assessment with the minimum necessary privilege - skipped the
    airmon-ng path entirely and fell through to the raw ``iw`` calls below, which
    were attempted regardless and would have failed with EPERM anyway. Asking about
    the capability is both more permissive where that is correct and more accurate:
    if the attempt fails, the failure is classified as insufficient_privileges from
    a real EPERM rather than silently never tried.

    Falls back to a live read when the manager has no recorded capability set, so a
    caller that constructs a stub manager is not silently treated as unprivileged.
    """
    if getattr(tool_manager, "is_root", False):
        return True
    held = getattr(tool_manager, "capabilities", None)
    if held is None:
        held = effective_capabilities()
    return "cap_net_admin" in set(held)


class InterfaceManager:
    """Manages wireless interfaces lifecycle."""

    def __init__(self, tool_manager: ToolManager):
        self.tool_manager = tool_manager

    def list_interfaces(self) -> List[str]:
        """List system interfaces."""
        from ...utils.system import get_interface_list

        return get_interface_list()

    def get_interface_info(self, interface: str) -> Optional[InterfaceInfo]:
        """Get interface info with deep checks."""
        cap = self.tool_manager.check_interface_deep(interface)
        if not cap.exists:
            return None

        info = InterfaceInfo(
            name=cap.name,
            type=cap.type,
            driver=cap.driver,
            chipset=cap.chipset,
            mac=cap.mac,
            supports_monitor=cap.supports_monitor,
            supports_injection=cap.supports_injection,
            is_up=cap.is_up,
            channel=cap.current_channel,
            extra={
                "monitor_tested": cap.monitor_tested,
                "injection_tested": cap.injection_tested,
                "injection_result": cap.injection_test_result,
                "channels": cap.channels,
            },
        )
        return info

    def set_interface_up(self, interface: str) -> Tuple[bool, str]:
        """Set interface up."""
        if not check_interface_exists(interface):
            return False, f"Interface {interface} does not exist"

        exit_code, stdout, stderr, _ = run_command(["ip", "link", "set", interface, "up"], timeout=5)
        if exit_code == 0:
            return True, "Interface up"
        else:
            # Try ifconfig fallback
            exit_code2, stdout2, stderr2, _ = run_command(["ifconfig", interface, "up"], timeout=5)
            if exit_code2 == 0:
                return True, "Interface up (via ifconfig)"
            return False, f"Failed to set up: {stderr} {stderr2}"

    def set_interface_down(self, interface: str) -> Tuple[bool, str]:
        """Set interface down."""
        if not check_interface_exists(interface):
            return False, f"Interface {interface} does not exist"

        exit_code, stdout, stderr, _ = run_command(["ip", "link", "set", interface, "down"], timeout=5)
        if exit_code == 0:
            return True, "Interface down"
        else:
            exit_code2, stdout2, stderr2, _ = run_command(["ifconfig", interface, "down"], timeout=5)
            if exit_code2 == 0:
                return True, "Interface down (via ifconfig)"
            return False, f"Failed to set down: {stderr} {stderr2}"

    def set_channel(self, interface: str, channel: int) -> Tuple[bool, str]:
        """Set channel via iw."""
        if not check_interface_exists(interface):
            return False, f"Interface {interface} does not exist"

        # Validate channel
        if not 1 <= channel <= 196:
            return False, f"Invalid channel {channel}"

        # Try iw first
        exit_code, stdout, stderr, _ = run_command(["iw", "dev", interface, "set", "channel", str(channel)], timeout=5)
        if exit_code == 0:
            return True, f"Channel set to {channel} via iw"

        # Try iwconfig fallback
        exit_code2, stdout2, stderr2, _ = run_command(["iwconfig", interface, "channel", str(channel)], timeout=5)
        if exit_code2 == 0:
            return True, f"Channel set to {channel} via iwconfig"

        return False, f"Failed to set channel: {stderr} {stderr2}"

    def create_monitor_interface(self, interface: str, channel: int = None) -> Tuple[bool, str, Optional[str]]:
        """
        Create monitor interface via airmon-ng or iw.

        Returns (success, message, monitor_interface_name)
        """
        if not check_interface_exists(interface):
            return False, f"Interface {interface} does not exist", None

        # Try airmon-ng first (handles driver quirks)
        tool_info = self.tool_manager.check_tool_deep("airmon-ng")
        if tool_info.available and _can_admin_interfaces(self.tool_manager):
            cmd = ["airmon-ng", "start", interface]
            if channel:
                cmd.append(str(channel))

            exit_code, stdout, stderr, _ = run_command(cmd, timeout=10)
            combined = stdout + stderr

            if exit_code == 0:
                # Parse monitor interface name
                # Example: (mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)
                m = re.search(r"on\s+\[phy\d+\](\w+mon)", combined)
                if m:
                    mon_iface = m.group(1)
                    return True, f"Monitor interface {mon_iface} created via airmon-ng", mon_iface

                # Fallback: look for mon interface in output
                # airmon-ng without args lists
                exit_code2, stdout2, stderr2, _ = run_command(["airmon-ng"], timeout=5)
                # Try to find new interface
                # For simplicity, check if wlan0mon exists
                for suffix in ["mon", "mon0"]:
                    test_iface = interface + suffix if not interface.endswith("mon") else interface
                    if check_interface_exists(test_iface):
                        return True, f"Monitor interface {test_iface} created via airmon-ng", test_iface

                # If we can't parse, assume wlan0mon
                assumed = interface + "mon" if not interface.endswith("mon") else interface
                if check_interface_exists(assumed):
                    return True, f"Monitor interface {assumed} created via airmon-ng (assumed)", assumed

                return True, "Monitor mode enabled via airmon-ng but interface name unclear", None
            else:
                # airmon-ng failed, try iw
                pass

        # Try iw method: iw dev <iface> set type monitor
        # First set down
        self.set_interface_down(interface)

        exit_code, stdout, stderr, _ = run_command(["iw", "dev", interface, "set", "type", "monitor"], timeout=5)
        if exit_code == 0:
            self.set_interface_up(interface)
            return True, f"Monitor mode set via iw for {interface}", interface

        # Try iwconfig
        exit_code2, stdout2, stderr2, _ = run_command(["iwconfig", interface, "mode", "Monitor"], timeout=5)
        if exit_code2 == 0:
            self.set_interface_up(interface)
            return True, f"Monitor mode set via iwconfig for {interface}", interface

        self.set_interface_up(interface)
        return False, f"Failed to create monitor: {stderr} {stderr2}", None

    def remove_monitor_interface(self, monitor_interface: str, original_interface: str = None) -> Tuple[bool, str]:
        """Remove monitor interface via airmon-ng stop or iw."""
        if not check_interface_exists(monitor_interface):
            return False, f"Monitor interface {monitor_interface} does not exist"

        # Try airmon-ng stop
        tool_info = self.tool_manager.check_tool_deep("airmon-ng")
        if tool_info.available and _can_admin_interfaces(self.tool_manager):
            exit_code, stdout, stderr, _ = run_command(["airmon-ng", "stop", monitor_interface], timeout=10)
            if exit_code == 0:
                return True, f"Monitor interface {monitor_interface} removed via airmon-ng"

        # Try iw: set back to managed
        self.set_interface_down(monitor_interface)
        exit_code, stdout, stderr, _ = run_command(
            ["iw", "dev", monitor_interface, "set", "type", "managed"], timeout=5
        )
        if exit_code == 0:
            self.set_interface_up(monitor_interface)
            return True, f"Monitor interface {monitor_interface} set to managed via iw"

        # Try deleting interface via iw
        exit_code2, stdout2, stderr2, _ = run_command(["iw", "dev", monitor_interface, "del"], timeout=5)
        if exit_code2 == 0:
            return True, f"Monitor interface {monitor_interface} deleted via iw"

        self.set_interface_up(monitor_interface)
        return False, f"Failed to remove monitor: {stderr} {stderr2}"

    def change_mac(self, interface: str, mac: str = None, random: bool = False) -> Tuple[bool, str, Optional[str]]:
        """
        Change MAC via macchanger.

        Returns (success, message, new_mac)
        """
        if not check_interface_exists(interface):
            return False, f"Interface {interface} does not exist", None

        if mac:
            valid, msg = validate_mac(mac)
            if not valid:
                return False, f"Invalid MAC: {msg}", None
            mac = normalize_mac(mac)

        tool_info = self.tool_manager.check_tool_deep("macchanger")
        if not tool_info.available:
            return False, "macchanger not available", None

        # Interface must be down for some drivers
        was_up = self.tool_manager.check_interface_deep(interface).is_up
        if was_up:
            self.set_interface_down(interface)

        if random:
            cmd = ["macchanger", "-r", interface]
        elif mac:
            cmd = ["macchanger", "-m", mac, interface]
        else:
            cmd = ["macchanger", "-r", interface]

        exit_code, stdout, stderr, _ = run_command(cmd, timeout=5)
        combined = stdout + stderr

        if was_up:
            self.set_interface_up(interface)

        if exit_code == 0:
            # Parse new MAC
            m = re.search(r"New MAC:\s*([0-9A-Fa-f:]{17})", combined)
            if m:
                new_mac = m.group(1).upper()
                return True, f"MAC changed to {new_mac}", new_mac
            # Also check Current MAC after change
            m = re.search(r"Current MAC:\s*([0-9A-Fa-f:]{17})", combined)
            if m:
                new_mac = m.group(1).upper()
                return True, f"MAC changed to {new_mac}", new_mac
            return True, "MAC changed (new MAC unclear)", None
        else:
            return False, f"Failed to change MAC: {combined}", None

    def unblock_rfkill(self) -> Tuple[bool, str]:
        """Unblock all rfkill."""
        tool_info = self.tool_manager.check_tool_deep("rfkill")
        if not tool_info.available:
            return False, "rfkill not available"

        exit_code, stdout, stderr, _ = run_command(["rfkill", "unblock", "all"], timeout=5)
        if exit_code == 0:
            return True, "rfkill unblocked all"
        else:
            exit_code2, stdout2, stderr2, _ = run_command(["rfkill", "unblock", "wifi"], timeout=5)
            if exit_code2 == 0:
                return True, "rfkill unblocked wifi"
            return False, f"Failed to unblock rfkill: {stderr} {stderr2}"

    def get_supported_channels(self, interface: str) -> List[int]:
        """Get channels supported by the phy that owns this interface.

        `iw list` prints one block per phy, so parsing the whole output merges
        the channels of every radio in the system and answers a question about
        `interface` with data that may not apply to it. Restrict to the owning
        phy, and exclude channels the driver reports as disabled.
        """
        channels: List[int] = []

        try:
            # 5s was too tight on a busy runner with several radios.
            exit_code, stdout, stderr, _ = run_command(["iw", "list"], timeout=15)
            if exit_code != 0:
                return []

            phy = self._phy_name_for_interface(interface)
            block = self._phy_block_for(stdout, interface, phy)
            for line in block.splitlines():
                # Current iw prints the frequency with a decimal place, needed
                # for 6 GHz half-channel spacing; older releases print an
                # integer. Accept both.
                #   * 2412.0 MHz [1] (20.0 dBm)
                #   * 2412 MHz [1] (20.0 dBm)
                #   * 5745.0 MHz [149] (disabled)
                m = re.search(r"\*\s+\d+(?:\.\d+)?\s+MHz\s+\[(\d+)\]", line)
                if not m:
                    continue
                if "disabled" in line:
                    continue
                try:
                    ch = int(m.group(1))
                except ValueError:
                    continue
                if ch not in channels:
                    channels.append(ch)
        except Exception:
            pass

        return sorted(channels)

    @staticmethod
    def _phy_name_for_interface(interface: str) -> Optional[str]:
        """Resolve an interface to its phy (e.g. "wlan1mon" -> "phy1") via sysfs.

        Current `iw list` output does not enumerate interfaces, so the phy cannot
        be found by scanning it. The phy80211 symlink is authoritative and works
        for virtual interfaces created by airmon-ng too.
        """
        link = f"/sys/class/net/{interface}/phy80211"
        try:
            target = os.readlink(link)
        except OSError:
            return None
        name = os.path.basename(os.path.normpath(target))
        return name if re.fullmatch(r"phy\d+", name) else None

    # `iw list` opens each radio's block with "Wiphy phy0" in current iw
    # releases and with "phy#0" in older ones. Split on either.
    _PHY_HEADER = re.compile(r"(?m)^(?=Wiphy\s+phy|phy#)")

    @classmethod
    def _phy_block_for(cls, iw_list_output: str, interface: str, phy_name: Optional[str] = None) -> str:
        """Return the `iw list` block describing this interface's radio.

        Prefers the phy resolved from sysfs. Falls back to locating an
        "Interface <name>" line for older iw releases, then to the whole output,
        so a partial answer is still returned rather than nothing.
        """
        blocks = re.split(cls._PHY_HEADER, iw_list_output)

        if phy_name:
            index = phy_name[3:]  # "phy1" -> "1"
            for block in blocks:
                header = block.split("\n", 1)[0].strip()
                if header in (f"Wiphy {phy_name}", f"phy#{index}"):
                    return block

        for block in blocks:
            if re.search(rf"(?m)^\s*Interface\s+{re.escape(interface)}\s*$", block):
                return block

        return iw_list_output
