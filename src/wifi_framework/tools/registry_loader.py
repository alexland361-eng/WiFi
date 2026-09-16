"""
Registry loader - loads all adapters into global registry.
"""
from __future__ import annotations

from ..core.execution.registry import CapabilityRegistry


def load_all_adapters(registry: CapabilityRegistry = None) -> CapabilityRegistry:
    """Load all adapters into registry."""
    if registry is None:
        from ..core.execution.registry import get_global_registry

        registry = get_global_registry()

    # Import all adapter modules to trigger registration
    # Interface - includes aircrack suite
    from .adapters.interface import airmon, aireplay, ethtool, iw, iwconfig, rfkill

    # Discovery
    from .adapters.discovery import airodump, horst, kismet, wash, wavemon

    # Capture - includes termshark, mitmproxy, airbase
    from .adapters.capture import dumpcap, tcpdump, termshark, tshark

    # WPS
    from .adapters.wps import bully, pixiewps, reaver

    # WPA - includes aircrack suite
    from .adapters.wpa import aircrack, hashcat, hcxdumptool, hcxpcapngtool, john

    # Network - includes DNS enum
    from .adapters.network import arp_scan, dig, dns_enum, fping, netdiscover, nmap

    # Enumeration - includes advanced
    from .adapters.enumeration import advanced, generic

    # Protocol
    from .adapters.protocol import bettercap, macchanger, scapy_adapter

    # Vuln
    from .adapters.vuln import nuclei_nikto

    # Register each
    modules = [
        iw,
        iwconfig,
        airmon,
        aireplay,
        rfkill,
        ethtool,
        airodump,
        wash,
        kismet,
        horst,
        wavemon,
        tshark,
        tcpdump,
        dumpcap,
        termshark,
        reaver,
        bully,
        pixiewps,
        hcxdumptool,
        hcxpcapngtool,
        hashcat,
        john,
        aircrack,
        nmap,
        arp_scan,
        netdiscover,
        fping,
        dig,
        dns_enum,
        generic,
        advanced,
        macchanger,
        bettercap,
        scapy_adapter,
        nuclei_nikto,
    ]

    for mod in modules:
        if hasattr(mod, "register"):
            try:
                mod.register(registry)
            except Exception as e:
                print(f"Warning: Failed to register {mod.__name__}: {e}")

    return registry
