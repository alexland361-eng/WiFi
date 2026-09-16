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
    # Interface
    from .adapters.interface import airmon, ethtool, iw, iwconfig, rfkill

    # Discovery
    from .adapters.discovery import airodump, horst, kismet, wash, wavemon

    # Capture
    from .adapters.capture import dumpcap, tcpdump, tshark

    # WPS
    from .adapters.wps import bully, pixiewps, reaver

    # WPA
    from .adapters.wpa import hashcat, hcxdumptool, hcxpcapngtool, john

    # Network
    from .adapters.network import arp_scan, dig, fping, netdiscover, nmap

    # Enumeration
    from .adapters.enumeration import generic

    # Protocol
    from .adapters.protocol import bettercap, macchanger, scapy_adapter

    # Register each
    modules = [
        iw,
        iwconfig,
        airmon,
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
        reaver,
        bully,
        pixiewps,
        hcxdumptool,
        hcxpcapngtool,
        hashcat,
        john,
        nmap,
        arp_scan,
        netdiscover,
        fping,
        dig,
        generic,
        macchanger,
        bettercap,
        scapy_adapter,
    ]

    for mod in modules:
        if hasattr(mod, "register"):
            try:
                mod.register(registry)
            except Exception as e:
                print(f"Warning: Failed to register {mod.__name__}: {e}")

    return registry
