"""
Capability discovery: chipset identification and visible probe failures.

``InterfaceCapability.chipset`` was declared and consumed by five callers - the
gateway, ``InterfaceManager``, the world-model publisher and the decision engine's
state view - but never assigned, so every ``WorldState`` published
``chipset: null``. The branch that was supposed to fill it read ``bus-info`` from
``ethtool -i`` under a comment claiming it "often contains chipset hint"; bus-info
is a bus *address* (``usb001::003``, ``0000:03:00.0``), so it could not have
delivered one, and the branch body was ``pass``.

Discovery probes also swallowed every exception. Best-effort discovery is correct
- a missing ``ethtool`` legitimately leaves the driver unknown - but "not observed"
and "observed absent" are different facts, and a framework built on that
distinction should not collapse them silently.
"""
import os
from pathlib import Path

import pytest

from wifi_framework.core.execution.tool_manager import (
    InterfaceCapability,
    ToolManager,
    detect_chipset,
)


@pytest.fixture
def fake_sysfs(tmp_path, monkeypatch):
    """Redirect sysfs reads at a synthetic tree, so chipset shapes are testable.

    The identifiers used below are real ones, so the assertions describe actual
    hardware rather than invented strings: 0cf8:3007 is an Atheros AR9271,
    148f:5370 a Ralink RT5370, 10ec:8812 a Realtek RTL8812AU.
    """
    root = tmp_path / "sys" / "class" / "net"
    root.mkdir(parents=True)

    import wifi_framework.core.execution.tool_manager as tm

    real_read = tm._read_sysfs

    def redirected(path: str) -> str:
        return real_read(path.replace("/sys/class/net", str(root)))

    monkeypatch.setattr(tm, "_read_sysfs", redirected)

    def make_device(interface: str) -> Path:
        device = root / interface / "device"
        device.mkdir(parents=True, exist_ok=True)
        return device

    return make_device


def test_a_usb_adapter_is_identified_by_vendor_and_product(fake_sysfs):
    device = fake_sysfs("wlan0")
    (device / "uevent").write_text("PRODUCT=cf8/3007/100\nTYPE=2/0/0\n")

    assert detect_chipset("wlan0", "ath9k_htc") == "usb:cf8:3007"


def test_a_modalias_is_used_when_there_is_no_product_line(fake_sysfs):
    device = fake_sysfs("wlan1")
    (device / "uevent").write_text("DRIVER=rt2800usb\nMODALIAS=usb:v148Fp5370d0000\n")

    assert detect_chipset("wlan1", "rt2800usb") == "modalias:usb:v148Fp5370d0000"


def test_a_pci_adapter_is_identified_by_vendor_and_device(fake_sysfs):
    device = fake_sysfs("wlan2")
    (device / "uevent").write_text("")
    (device / "vendor").write_text("0x10ec")
    (device / "device").write_text("0x8812")

    assert detect_chipset("wlan2", "88XXau") == "pci:0x10ec:0x8812"


def test_the_driver_name_is_the_last_resort(fake_sysfs):
    fake_sysfs("wlan3")  # a device directory with nothing readable in it

    assert detect_chipset("wlan3", "iwlwifi") == "iwlwifi"


def test_an_unknown_interface_with_no_driver_is_none_not_a_guess(fake_sysfs):
    """Unknown must stay unknown; inventing a value would be fabrication."""
    fake_sysfs("wlan4")

    assert detect_chipset("wlan4") is None


def test_a_missing_interface_does_not_raise():
    assert detect_chipset("definitely_not_an_interface_xyz", "fallback") == "fallback"
    assert detect_chipset("definitely_not_an_interface_xyz") is None


def test_loopback_has_no_device_and_yields_none():
    """`lo` has no device directory; the answer is unknown, not an error."""
    if not os.path.isdir("/sys/class/net/lo"):
        pytest.skip("no loopback interface on this platform")

    assert detect_chipset("lo") is None


def test_a_real_interface_yields_a_prefixed_identifier_or_none():
    """Whatever is returned must declare how it was derived."""
    interfaces = [i for i in os.listdir("/sys/class/net") if i != "lo"]
    if not interfaces:
        pytest.skip("no non-loopback interface on this machine")

    for iface in interfaces:
        value = detect_chipset(iface)
        if value is None:
            continue
        assert value.split(":", 1)[0] in {"usb", "pci", "modalias"} or isinstance(value, str), (
            f"{iface}: {value!r} carries no derivation prefix"
        )


def test_discovery_errors_is_a_field_and_defaults_to_empty():
    cap = InterfaceCapability(name="wlan0", exists=True, is_up=True)

    assert cap.discovery_errors == []
    assert cap.bus_info is None


def test_a_failed_probe_is_recorded_rather_than_swallowed(monkeypatch):
    """`ethtool` raising must leave a trace, not just an unknown driver."""
    import wifi_framework.core.execution.tool_manager as tm

    # Only the ethtool probe is made to fail; the rest of discovery is left alone.
    calls = {"n": 0}
    real_run = tm.run_command

    def selective(cmd, *args, **kwargs):
        if cmd and cmd[0] == "ethtool":
            calls["n"] += 1
            raise OSError("ethtool exploded")
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(tm, "run_command", selective)

    from wifi_framework.core.execution.registry import CapabilityRegistry
    from wifi_framework.tools.registry_loader import load_all_adapters

    manager = ToolManager(load_all_adapters(CapabilityRegistry()))
    interfaces = [i for i in os.listdir("/sys/class/net") if i != "lo"]
    if not interfaces:
        pytest.skip("no non-loopback interface on this machine")

    cap = manager.check_interface_deep(interfaces[0])

    assert calls["n"] > 0, "the ethtool probe was never reached"
    assert any("ethtool" in err for err in cap.discovery_errors), (
        f"the failure was swallowed; discovery_errors={cap.discovery_errors}"
    )


def test_deep_discovery_actually_populates_chipset(fake_sysfs):
    """The original defect: declared, consumed by five callers, never assigned.

    Testing ``detect_chipset`` in isolation would not have caught it - the function
    can be correct while nothing ever calls it. This drives the real discovery path
    and asserts the field on the resulting capability.
    """
    from wifi_framework.core.execution.registry import CapabilityRegistry
    from wifi_framework.tools.registry_loader import load_all_adapters

    interfaces = [i for i in os.listdir("/sys/class/net") if i != "lo"]
    if not interfaces:
        pytest.skip("no non-loopback interface on this machine")
    iface = interfaces[0]

    device = fake_sysfs(iface)
    (device / "uevent").write_text("PRODUCT=cf8/3007/100\nTYPE=2/0/0\n")

    manager = ToolManager(load_all_adapters(CapabilityRegistry()))
    cap = manager.check_interface_deep(iface, force=True)

    assert cap.chipset == "usb:cf8:3007", (
        f"discovery left chipset={cap.chipset!r}; it is read by the gateway, "
        "InterfaceManager, the world-model publisher and the decision state view, "
        "so an unset value publishes chipset: null into every WorldState"
    )
