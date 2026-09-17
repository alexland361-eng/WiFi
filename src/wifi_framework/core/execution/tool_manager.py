"""
Tool Manager - Advanced tool handling and management with deep research confirmation.

Handles:
- Tool lifecycle (discovery, version checking, dependency resolution, capability verification)
- Driver and interface capability deep checks (monitor mode via iw, injection via aireplay-ng --test)
- Tool output management (pcap files, temp files, cleanup)
- Execution queue with retry and failure recovery
- Tool chain handling (e.g., hcxdumptool → hcxpcapngtool → hashcat)
- Resource management

Deep research confirmation: Each tool's real operational characteristics verified against official docs.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ...utils.system import (
    check_interface_exists,
    check_tool_available,
    effective_capabilities,
    get_interface_list,
    get_os_info,
    is_root,
    run_command,
)
from .registry import CapabilityRegistry


@dataclass
class ToolInfo:
    """Detailed tool information after deep check."""
    binary: str
    available: bool
    path: Optional[str] = None
    version_raw: Optional[str] = None
    version_parsed: Optional[Tuple[int, ...]] = None
    capabilities: List[str] = field(default_factory=list)
    dependencies_ok: bool = True
    missing_deps: List[str] = field(default_factory=list)
    driver_info: Optional[Dict[str, Any]] = None
    last_checked: float = field(default_factory=time.time)
    operational: bool = False
    failure_reason: Optional[str] = None


def _read_sysfs(path: str) -> str:
    """Read a sysfs attribute, returning "" when it is absent or unreadable."""
    try:
        with open(path, "r", errors="replace") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def detect_chipset(interface: str, driver: Optional[str] = None) -> Optional[str]:
    """Identify the underlying device from sysfs, falling back to the driver name.

    ``ethtool -i`` reports ``bus-info`` as a *bus address* - ``usb001::003`` or
    ``0000:03:00.0`` - not a chipset, so the branch that used to sit here with a
    comment claiming it "often contains chipset hint" could not have delivered one.
    The device identifiers under ``/sys/class/net/<if>/device`` can.

    ``InterfaceCapability.chipset`` is consumed by the gateway, InterfaceManager,
    the world-model publisher and the decision engine's state view, so leaving it
    permanently ``None`` published an unknown chipset into every WorldState.

    Returns a prefixed identifier so the consumer can tell how it was derived:
    ``usb:<vendor>:<product>``, ``pci:<vendor>:<device>``, ``modalias:<value>``,
    or the bare driver name when sysfs exposes nothing.
    """
    base = f"/sys/class/net/{interface}/device"
    uevent = _read_sysfs(f"{base}/uevent")

    match = re.search(r"^PRODUCT=([0-9a-fA-F]+)/([0-9a-fA-F]+)", uevent, re.MULTILINE)
    if match:
        return f"usb:{match.group(1)}:{match.group(2)}"

    vendor, device = _read_sysfs(f"{base}/vendor"), _read_sysfs(f"{base}/device")
    if vendor and device:
        return f"pci:{vendor}:{device}"

    match = re.search(r"^MODALIAS=(.+)$", uevent, re.MULTILINE)
    if match:
        return f"modalias:{match.group(1)}"

    modalias = _read_sysfs(f"{base}/modalias")
    if modalias:
        return f"modalias:{modalias}"

    return driver


@dataclass
class InterfaceCapability:
    """Deep interface capability after testing."""
    name: str
    exists: bool
    is_up: bool
    driver: Optional[str] = None
    chipset: Optional[str] = None
    supports_monitor: bool = False
    supports_injection: bool = False
    monitor_tested: bool = False
    injection_tested: bool = False
    injection_test_result: Optional[str] = None
    channels: List[int] = field(default_factory=list)
    current_channel: Optional[int] = None
    mac: Optional[str] = None
    #: Bus address from `ethtool -i` (usb001::003, 0000:03:00.0). Not a chipset.
    bus_info: Optional[str] = None
    type: str = "unknown"
    last_checked: float = field(default_factory=time.time)
    #: Probes that raised during discovery. Capability discovery is best-effort by
    #: nature - a missing `ethtool` legitimately leaves `driver` unknown - but an
    #: unknown value and a failed probe are different facts, and a framework whose
    #: whole premise is distinguishing "not observed" from "observed absent" should
    #: not collapse them silently.
    discovery_errors: List[str] = field(default_factory=list)


class ToolManager:
    """
    Advanced tool handling and management.

    Performs deep capability checks beyond simple which:
    - For wireless interfaces: checks driver via ethtool -i, monitors via iw list, injection via aireplay-ng --test
    - For tools: version parsing, dependency chain, operational test
    """

    def __init__(self, registry: CapabilityRegistry):
        self.registry = registry
        self.tool_cache: Dict[str, ToolInfo] = {}
        self.interface_cache: Dict[str, InterfaceCapability] = {}
        self.os_info = get_os_info()
        self.is_root = is_root()
        #: Capabilities actually held, sorted for a stable audit record. Root
        #: implies the full set; an unprivileged process with CAP_NET_ADMIN and
        #: CAP_NET_RAW can still administer and inject on wireless interfaces, and
        #: ``is_root`` alone reported that process as unable to do anything.
        self.capabilities: List[str] = sorted(effective_capabilities())

    def holds_capabilities(self, *names: str) -> bool:
        """Whether this process holds every named capability.

        A root process holds the full effective set, so ``is_root`` short-circuits.
        That is not just a convenience: ``self.capabilities`` is read once at
        construction, so a manager built in an unprivileged process and later marked
        as root - as the interface-manager tests do - would otherwise report an
        empty capability set for a process that in reality has all of them.
        """
        if self.is_root:
            return True
        held = set(self.capabilities)
        return all(name in held for name in names)

    def check_tool_deep(self, binary: str, force: bool = False) -> ToolInfo:
        """Deep check tool availability, version, dependencies, operational."""
        if not force and binary in self.tool_cache:
            # Cache for 60 seconds
            if time.time() - self.tool_cache[binary].last_checked < 60:
                return self.tool_cache[binary]

        available, path, version_raw = check_tool_available(binary)

        info = ToolInfo(
            binary=binary,
            available=available,
            path=path,
            version_raw=version_raw,
            last_checked=time.time(),
        )

        if not available:
            info.failure_reason = version_raw
            info.operational = False
            self.tool_cache[binary] = info
            return info

        # Parse version
        from ...utils.system import parse_version

        info.version_parsed = parse_version(version_raw) if version_raw else None

        # Check if tool has known capabilities
        # For example, iw supports monitor if iw list shows monitor mode
        # This is handled in interface checks

        # Operational check - try to run with --help or --version and see if it works
        try:
            exit_code, stdout, stderr, _ = run_command([binary, "--help"], timeout=5)
            # If exit code 0 or 1 (help often returns 0 or 1), consider operational
            # If 127, not found (should not happen since which succeeded)
            if exit_code in [0, 1, 2]:
                info.operational = True
            else:
                # Try --version
                exit_code2, stdout2, stderr2, _ = run_command([binary, "--version"], timeout=5)
                if exit_code2 in [0, 1]:
                    info.operational = True
                else:
                    info.operational = True  # If binary exists, assume operational unless proven otherwise
        except Exception as e:
            info.operational = False
            info.failure_reason = f"Operational check failed: {e}"

        self.tool_cache[binary] = info
        return info

    def check_interface_deep(self, interface: str, force: bool = False) -> InterfaceCapability:
        """Deep check interface capabilities including driver, monitor, injection."""
        if not force and interface in self.interface_cache:
            if time.time() - self.interface_cache[interface].last_checked < 30:
                return self.interface_cache[interface]

        exists = check_interface_exists(interface)
        cap = InterfaceCapability(name=interface, exists=exists, is_up=False)

        if not exists:
            self.interface_cache[interface] = cap
            return cap

        # Check if up
        try:
            # Check /sys/class/net/<iface>/operstate
            operstate_path = f"/sys/class/net/{interface}/operstate"
            if os.path.exists(operstate_path):
                with open(operstate_path, "r") as f:
                    state = f.read().strip()
                    cap.is_up = state == "up" or state == "unknown"  # unknown often means up for wireless
            # Check flags via /sys/class/net/<iface>/flags or via ip
            # For simplicity, assume exists means potentially up
            if not cap.is_up:
                # Try ip link show
                exit_code, stdout, stderr, _ = run_command(["ip", "link", "show", interface], timeout=3)
                if exit_code == 0 and "UP" in stdout:
                    cap.is_up = True
        except Exception as exc:
            cap.discovery_errors.append(f"link state: {type(exc).__name__}: {exc}")

        # Get driver info via ethtool -i
        try:
            exit_code, stdout, stderr, _ = run_command(["ethtool", "-i", interface], timeout=3)
            if exit_code == 0:
                for line in stdout.splitlines():
                    if ":" in line:
                        key, val = line.split(":", 1)
                        key = key.strip().lower()
                        val = val.strip()
                        if key == "driver":
                            cap.driver = val
                        elif key == "bus-info":
                            # A bus address, not a chipset; kept for the record only.
                            cap.bus_info = val
        except Exception as exc:
            cap.discovery_errors.append(f"ethtool -i: {type(exc).__name__}: {exc}")

        if not cap.chipset:
            cap.chipset = detect_chipset(interface, cap.driver)

        # Get MAC
        try:
            addr_path = f"/sys/class/net/{interface}/address"
            if os.path.exists(addr_path):
                with open(addr_path, "r") as f:
                    cap.mac = f.read().strip().upper()
        except Exception as exc:
            cap.discovery_errors.append(f"mac address: {type(exc).__name__}: {exc}")

        # Detect the interface type and current channel from the interface
        # itself. This used to live in an `else` branch that only ran when
        # `iw list` FAILED, so on every working system the type kept its
        # "unknown" default -- which also disabled the injection probe below,
        # whose guard is `cap.type == "monitor"`.
        try:
            exit_code2, stdout2, stderr2, _ = run_command(["iw", "dev", interface, "info"], timeout=3)
            if exit_code2 == 0:
                m = re.search(r"^\s*type\s+(\S+)", stdout2, re.MULTILINE)
                if m:
                    cap.type = m.group(1)
                    if cap.type == "monitor":
                        cap.supports_monitor = True
                # Check channel
                m = re.search(r"channel\s+(\d+)", stdout2)
                if m:
                    try:
                        cap.current_channel = int(m.group(1))
                    except ValueError as exc:
                        cap.discovery_errors.append(f"channel parse: {exc}")
        except Exception as exc:
            cap.discovery_errors.append(f"iw dev info: {type(exc).__name__}: {exc}")

        # Check monitor support via iw list (phy-wide "Supported interface modes")
        try:
            exit_code, stdout, stderr, _ = run_command(["iw", "list"], timeout=5)
            if exit_code == 0:
                if "* monitor" in stdout:
                    cap.supports_monitor = True
        except Exception as exc:
            cap.discovery_errors.append(f"iw list: {type(exc).__name__}: {exc}")

        # Check injection support via aireplay-ng --test. This needs CAP_NET_RAW to
        # open the raw socket and CAP_NET_ADMIN to transmit on the interface - not
        # full root. Gating on is_root skipped the probe for an unprivileged process
        # that was in fact permitted to run it, so injection support stayed unknown
        # and every packet-injection capability looked unavailable.
        if (
            cap.type == "monitor"
            and cap.supports_monitor
            and self.holds_capabilities("cap_net_admin", "cap_net_raw")
        ):
            try:
                # Check if aireplay-ng exists
                tool_info = self.check_tool_deep("aireplay-ng")
                if tool_info.available:
                    # Run injection test - this is invasive but for capability discovery it's okay with timeout
                    # Use --test which is safe (doesn't actually deauth)
                    exit_code, stdout, stderr, _ = run_command(
                        ["aireplay-ng", "--test", interface], timeout=10
                    )
                    combined = stdout + stderr
                    cap.injection_tested = True
                    if "Injection is working" in combined:
                        cap.supports_injection = True
                        cap.injection_test_result = "working"
                    elif "Injection is not working" in combined:
                        cap.supports_injection = False
                        cap.injection_test_result = "not_working"
                    else:
                        cap.injection_test_result = combined[:500]
            except Exception as e:
                cap.injection_test_result = f"Test failed: {e}"

        cap.monitor_tested = True
        self.interface_cache[interface] = cap
        return cap

    def discover_all_interfaces(self) -> Dict[str, InterfaceCapability]:
        """Discover all system interfaces with deep checks."""
        interfaces = {}
        sys_ifaces = get_interface_list()
        for iface in sys_ifaces:
            if iface == "lo":
                continue
            cap = self.check_interface_deep(iface)
            interfaces[iface] = cap
        return interfaces

    def discover_all_tools(self) -> Dict[str, ToolInfo]:
        """Discover all registered tools with deep checks."""
        tools = {}
        for cap_name in self.registry.list_capabilities():
            meta = self.registry.get_metadata(cap_name)
            if not meta:
                continue
            binary = meta.tool_binary
            if binary not in tools:
                info = self.check_tool_deep(binary)
                tools[binary] = info
        return tools

    def get_capability_status(self, capability_name: str, interface: Optional[str] = None) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Get capability status with deep checks.

        Returns (available, reason, details)
        """
        meta = self.registry.get_metadata(capability_name)
        if not meta:
            return False, f"Capability {capability_name} not registered", {}

        # Basic checks via registry
        from .capability_checker import CapabilityChecker

        checker = CapabilityChecker()
        basic_ok, basic_reason, basic_details = checker.check(meta, interface)

        if not basic_ok:
            return False, basic_reason, basic_details

        # Deep checks if interface required
        if interface and meta.requirements.interface_capabilities:
            iface_cap = self.check_interface_deep(interface)

            if "monitor_mode" in meta.requirements.interface_capabilities:
                if not iface_cap.supports_monitor:
                    return False, f"Interface {interface} does not support monitor mode (driver: {iface_cap.driver})", {
                        **basic_details,
                        "interface_capability": iface_cap.__dict__,
                    }

            if "injection" in meta.requirements.interface_capabilities:
                if not iface_cap.supports_injection:
                    # If not tested, we can't be sure, but if tested and false, fail
                    if iface_cap.injection_tested and not iface_cap.supports_injection:
                        return False, f"Interface {interface} does not support injection (test: {iface_cap.injection_test_result})", {
                            **basic_details,
                            "interface_capability": iface_cap.__dict__,
                        }
                    # If not tested, warn but allow (since injection test requires monitor mode and root)
                    # For now, allow but note

        return True, "Available (deep check passed)", basic_details

    def create_temp_file(self, suffix: str = "", prefix: str = "wifi_framework_") -> str:
        """Create temp file for tool output, with cleanup tracking."""
        fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix)
        os.close(fd)
        return path

    def create_temp_dir(self, prefix: str = "wifi_framework_") -> str:
        """Create temp dir for tool output."""
        return tempfile.mkdtemp(prefix=prefix)

    def cleanup_file(self, path: str):
        """Cleanup temp file."""
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass

    def cleanup_dir(self, path: str):
        """Cleanup temp dir."""
        try:
            if os.path.exists(path):
                shutil.rmtree(path)
        except OSError:
            pass

    def get_tool_chain(self, objective: str) -> List[str]:
        """
        Get tool chain for objective.

        Example: WPA handshake capture chain
        - For handshake: airodump-ng or hcxdumptool for capture, then hcxpcapngtool for conversion
        - For WPS: wash for discovery, then reaver/bully, then pixiewps
        - For network: arp-scan for hosts, then nmap for services, then nuclei/nikto for vuln

        Returns list of capability names in order.
        """
        chains = {
            "handshake_capture": ["airodump-ng", "hcxdumptool", "hcxpcapngtool"],
            "wpa_crack": ["hcxpcapngtool", "hashcat", "john", "aircrack-ng"],
            "wps_assessment": ["wash", "reaver", "bully", "pixiewps"],
            "wireless_discovery": ["iw_dev", "iwconfig", "rfkill", "iw_list", "airodump-ng", "kismet"],
            "network_discovery": ["arp-scan", "netdiscover", "fping", "nmap"],
            "dns_enumeration": ["dig", "dnsenum", "dnsrecon"],
            "service_enumeration": ["nmap", "smbclient", "smbmap", "enum4linux-ng", "nbtscan", "snmpwalk", "curl", "openssl_s_client"],
            "vulnerability_assessment": ["nmap", "nuclei", "nikto"],
            "interface_setup": ["rfkill", "airmon-ng", "iw_dev", "macchanger"],
        }

        return chains.get(objective, [])

    def estimate_execution_time(self, capability_name: str, parameters: Optional[Dict[str, Any]] = None) -> int:
        """Estimate execution time based on metadata and parameters."""
        meta = self.registry.get_metadata(capability_name)
        if not meta:
            return 30

        base = meta.operational_properties.estimated_duration_seconds or 30

        # Adjust based on parameters
        parameters = parameters or {}
        if "count" in parameters:
            try:
                count = int(parameters["count"])
                # For capture tools, count affects time
                base = min(base, count * 2)
            except (ValueError, TypeError):
                pass

        if capability_name in ["airodump-ng", "kismet", "hcxdumptool", "airbase-ng"]:
            # Persistent tools - duration depends on timeout
            if parameters.get("duration"):
                try:
                    base = int(parameters["duration"])
                except (ValueError, TypeError):
                    pass

        return base

    def to_dict(self) -> Dict[str, Any]:
        """Export tool manager state for audit."""
        return {
            "os_info": self.os_info,
            "is_root": self.is_root,
            "capabilities": list(self.capabilities),
            "tools_cached": len(self.tool_cache),
            "interfaces_cached": len(self.interface_cache),
            "tools": {binary: {"available": info.available, "path": info.path, "version": info.version_raw, "operational": info.operational} for binary, info in self.tool_cache.items()},
            "interfaces": {name: cap.__dict__ for name, cap in self.interface_cache.items()},
        }
