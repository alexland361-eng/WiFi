"""
Regression tests for interface discovery and channel handling.

These pin three defects found by verifying InterfaceManager against real
mac80211_hwsim radios in CI (see .github/workflows/tests.yml and
scripts/verify_wireless_hardware.py). Each is reproduced here without hardware
by stubbing run_command, so the suite catches a regression anywhere, not only
on a runner with a radio.

1. InterfaceCapability had no `last_checked` field, but check_interface_deep
   read it on every cache hit - so the second lookup of any interface raised
   AttributeError. The interface cache had never worked.
2. cap.type was assigned only in the branch taken when `iw list` FAILED, so on
   every working system the type stayed "unknown" - which also disabled the
   injection probe, whose guard is `cap.type == "monitor"`.
3. get_supported_channels parsed the whole `iw list` output, merging every
   radio's channels and ignoring its `interface` argument, and it counted
   channels the driver reports as disabled.
"""
import dataclasses

import pytest

from wifi_framework.core.execution import interface_manager as imod
from wifi_framework.core.execution import tool_manager as tmod
from wifi_framework.core.execution.interface_manager import InterfaceManager
from wifi_framework.core.execution.registry import CapabilityRegistry
from wifi_framework.core.execution.tool_manager import InterfaceCapability, ToolManager

IW_DEV_MANAGED = """Interface wlan0
\tifindex 3
\twdev 0x1
\taddr 02:00:00:00:00:00
\ttype managed
\ttxpower 20.00 dBm
"""

IW_DEV_MONITOR = """Interface wlan0
\tifindex 3
\twdev 0x1
\taddr 02:00:00:00:00:00
\ttype monitor
\tchannel 6 (2437 MHz), width: 20 MHz (no HT), center1: 2437 MHz
\ttxpower 20.00 dBm
"""

IW_LIST_TWO_PHYS = """phy#0
\tInterface wlan0
\t\ttype managed
\t\tSupported interface modes:
\t\t\t * managed
\t\t\t * AP
\t\t\t * monitor
\t\tFrequencies:
\t\t\t* 2412 MHz [1] (20.0 dBm)
\t\t\t* 2437 MHz [6] (20.0 dBm)
\t\t\t* 2462 MHz [11] (20.0 dBm)
\t\t\t* 2472 MHz [13] (disabled)
phy#1
\tInterface wlan1
\t\ttype managed
\t\tSupported interface modes:
\t\t\t * managed
\t\t\t * monitor
\t\tFrequencies:
\t\t\t* 5180 MHz [36] (20.0 dBm)
\t\t\t* 5745 MHz [149] (20.0 dBm)
"""


def stub_commands(monkeypatch, module, table):
    """Replace a module's run_command with one driven by `table`.

    Keys are matched against the longest matching command prefix, so
    ("iw", "dev", "wlan0", "info") wins over ("iw",).
    """
    calls = []

    def fake_run_command(cmd, timeout=30, **kwargs):
        calls.append(list(cmd))
        best = None
        for key in table:
            if list(cmd[: len(key)]) == list(key) and (best is None or len(key) > len(best)):
                best = key
        if best is None:
            return (0, "", "", 0.001)
        entry = table[best]
        return (entry[0], entry[1], entry[2] if len(entry) > 2 else "", 0.001)

    monkeypatch.setattr(module, "run_command", fake_run_command)
    return calls


def make_tool_manager(monkeypatch, iface="wlan0", exists=True):
    """A ToolManager whose filesystem and subprocess probes are stubbed."""
    monkeypatch.setattr(tmod, "check_interface_exists", lambda name: exists and name == iface)
    tm = ToolManager(CapabilityRegistry())
    tm.is_root = False  # keep the invasive aireplay-ng injection probe off
    tm.interface_cache.clear()
    return tm


# --------------------------------------------------------------------------
# Defect 1: the interface cache crashed on every hit
# --------------------------------------------------------------------------


def test_interface_capability_declares_last_checked():
    """The cache TTL check reads .last_checked, so the field must exist."""
    fields = {f.name for f in dataclasses.fields(InterfaceCapability)}
    assert "last_checked" in fields


def test_second_lookup_of_same_interface_does_not_raise(monkeypatch):
    """Regression: AttributeError on any repeated check_interface_deep call."""
    stub_commands(
        monkeypatch,
        tmod,
        {
            ("ethtool", "-i"): (1, "", "not supported"),
            ("iw", "dev", "wlan0", "info"): (0, IW_DEV_MANAGED),
            ("iw", "list"): (0, IW_LIST_TWO_PHYS),
        },
    )
    tm = make_tool_manager(monkeypatch)

    first = tm.check_interface_deep("wlan0")
    second = tm.check_interface_deep("wlan0")  # previously raised AttributeError

    assert first.exists is True
    assert second.exists is True


def test_second_lookup_of_absent_interface_does_not_raise(monkeypatch):
    """Absent interfaces are cached too, so they hit the same broken path."""
    stub_commands(monkeypatch, tmod, {})
    tm = make_tool_manager(monkeypatch, exists=False)

    tm.check_interface_deep("ghost0")
    again = tm.check_interface_deep("ghost0")

    assert again.exists is False


def test_cached_lookup_is_served_without_rerunning_probes(monkeypatch):
    """The cache must actually avoid work, not merely survive being read."""
    calls = stub_commands(
        monkeypatch,
        tmod,
        {
            ("ethtool", "-i"): (1, "", "not supported"),
            ("iw", "dev", "wlan0", "info"): (0, IW_DEV_MANAGED),
            ("iw", "list"): (0, IW_LIST_TWO_PHYS),
        },
    )
    tm = make_tool_manager(monkeypatch)

    tm.check_interface_deep("wlan0")
    after_first = len(calls)
    assert after_first > 0

    tm.check_interface_deep("wlan0")
    assert len(calls) == after_first, "a cache hit re-ran the probes"


def test_force_bypasses_the_cache(monkeypatch):
    calls = stub_commands(
        monkeypatch,
        tmod,
        {
            ("ethtool", "-i"): (1, "", "not supported"),
            ("iw", "dev", "wlan0", "info"): (0, IW_DEV_MANAGED),
            ("iw", "list"): (0, IW_LIST_TWO_PHYS),
        },
    )
    tm = make_tool_manager(monkeypatch)

    tm.check_interface_deep("wlan0")
    after_first = len(calls)
    tm.check_interface_deep("wlan0", force=True)
    assert len(calls) > after_first, "force=True was served from cache"


def test_change_mac_does_not_crash_requerying_the_interface(monkeypatch):
    """The CI failure: change_mac calls check_interface_deep on a cached iface."""
    stub_commands(
        monkeypatch,
        tmod,
        {
            ("ethtool", "-i"): (1, "", "not supported"),
            ("iw", "dev", "wlan0", "info"): (0, IW_DEV_MANAGED),
            ("iw", "list"): (0, IW_LIST_TWO_PHYS),
        },
    )
    tm = make_tool_manager(monkeypatch)
    im = InterfaceManager(tm)

    # Populate the cache the way get_interface_info does, then re-query.
    assert im.get_interface_info("wlan0") is not None

    monkeypatch.setattr(imod, "check_interface_exists", lambda name: name == "wlan0")
    stub_commands(
        monkeypatch,
        imod,
        {
            ("ip", "link", "set", "wlan0", "down"): (0, "", ""),
            ("ip", "link", "set", "wlan0", "up"): (0, "", ""),
            ("macchanger",): (1, "", "macchanger not installed in this test"),
        },
    )
    # macchanger is unavailable here, so this must fail cleanly - not raise.
    ok, message, new_mac = im.change_mac("wlan0", mac="02:00:00:00:00:AA")
    assert ok is False
    assert new_mac is None
    assert isinstance(message, str) and message


# --------------------------------------------------------------------------
# Defect 2: interface type was only detected when `iw list` failed
# --------------------------------------------------------------------------


def test_type_detected_when_iw_list_succeeds(monkeypatch):
    """The regression: `iw list` working left type at its "unknown" default."""
    stub_commands(
        monkeypatch,
        tmod,
        {
            ("ethtool", "-i"): (1, "", "not supported"),
            ("iw", "dev", "wlan0", "info"): (0, IW_DEV_MANAGED),
            ("iw", "list"): (0, IW_LIST_TWO_PHYS),
        },
    )
    tm = make_tool_manager(monkeypatch)

    cap = tm.check_interface_deep("wlan0")

    assert cap.type == "managed"
    assert cap.supports_monitor is True  # from "Supported interface modes"


def test_monitor_interface_reported_as_monitor(monkeypatch):
    stub_commands(
        monkeypatch,
        tmod,
        {
            ("ethtool", "-i"): (1, "", "not supported"),
            ("iw", "dev", "wlan0", "info"): (0, IW_DEV_MONITOR),
            ("iw", "list"): (0, IW_LIST_TWO_PHYS),
        },
    )
    tm = make_tool_manager(monkeypatch)

    cap = tm.check_interface_deep("wlan0")

    assert cap.type == "monitor"
    assert cap.supports_monitor is True
    assert cap.current_channel == 6


def test_type_detection_survives_iw_list_failing(monkeypatch):
    """The old fallback path must keep working, not be replaced by it."""
    stub_commands(
        monkeypatch,
        tmod,
        {
            ("ethtool", "-i"): (1, "", "not supported"),
            ("iw", "dev", "wlan0", "info"): (0, IW_DEV_MONITOR),
            ("iw", "list"): (1, "", "iw: command failed"),
        },
    )
    tm = make_tool_manager(monkeypatch)

    cap = tm.check_interface_deep("wlan0")

    assert cap.type == "monitor"


def test_type_stays_unknown_when_no_iw_at_all(monkeypatch):
    """Absent tooling must not be reported as a detected type."""
    stub_commands(
        monkeypatch,
        tmod,
        {
            ("ethtool", "-i"): (127, "", "Command not found"),
            ("iw",): (127, "", "Command not found"),
        },
    )
    tm = make_tool_manager(monkeypatch)

    cap = tm.check_interface_deep("wlan0")

    assert cap.type == "unknown"
    assert cap.supports_monitor is False


def test_injection_probe_gate_is_reachable_for_monitor_interface(monkeypatch):
    """The probe is guarded by cap.type == 'monitor'; that guard used to be dead."""
    probed = []

    stub_commands(
        monkeypatch,
        tmod,
        {
            ("ethtool", "-i"): (1, "", "not supported"),
            ("iw", "dev", "wlan0", "info"): (0, IW_DEV_MONITOR),
            ("iw", "list"): (0, IW_LIST_TWO_PHYS),
        },
    )
    tm = make_tool_manager(monkeypatch)
    tm.is_root = True

    # Make aireplay-ng appear installed and record that the probe ran.
    real_check_tool_deep = tm.check_tool_deep

    def fake_check_tool_deep(binary, force=False):
        info = real_check_tool_deep(binary, force=force)
        if binary == "aireplay-ng":
            info.available = True
        return info

    monkeypatch.setattr(tm, "check_tool_deep", fake_check_tool_deep)

    def record_aireplay(cmd, timeout=30, **kwargs):
        if cmd[:1] == ["aireplay-ng"]:
            probed.append(list(cmd))
            return (0, "Injection is working!", "", 0.001)
        return (0, "", "", 0.001)

    # Wrap the stub so aireplay-ng is observable.
    current = tmod.run_command

    def combined(cmd, timeout=30, **kwargs):
        if cmd[:1] == ["aireplay-ng"]:
            return record_aireplay(cmd, timeout, **kwargs)
        return current(cmd, timeout, **kwargs)

    monkeypatch.setattr(tmod, "run_command", combined)

    cap = tm.check_interface_deep("wlan0", force=True)

    assert cap.type == "monitor"
    assert probed, "the injection probe never ran for a monitor interface"
    assert cap.injection_tested is True
    assert cap.supports_injection is True


# --------------------------------------------------------------------------
# Defect 3: get_supported_channels ignored its argument and counted disabled
# --------------------------------------------------------------------------


def test_phy_block_is_scoped_to_the_owning_interface():
    block0 = InterfaceManager._phy_block_for(IW_LIST_TWO_PHYS, "wlan0")
    block1 = InterfaceManager._phy_block_for(IW_LIST_TWO_PHYS, "wlan1")

    assert "phy#0" in block0 and "phy#1" not in block0
    assert "phy#1" in block1 and "phy#0" not in block1


def test_phy_block_falls_back_when_interface_not_listed():
    """A partial answer beats no answer when the interface cannot be located."""
    assert InterfaceManager._phy_block_for(IW_LIST_TWO_PHYS, "wlan9") == IW_LIST_TWO_PHYS


def test_phy_block_match_is_not_a_substring_of_another_name():
    """`wlan1` must not match a `wlan10` line, which appears earlier here."""
    output = (
        "phy#0\n"
        "\tInterface wlan10\n"
        "\t\tFrequencies:\n"
        "\t\t\t* 2412 MHz [1] (20.0 dBm)\n"
        "phy#1\n"
        "\tInterface wlan1\n"
        "\t\tFrequencies:\n"
        "\t\t\t* 5180 MHz [36] (20.0 dBm)\n"
    )

    block = InterfaceManager._phy_block_for(output, "wlan1")

    assert "phy#1" in block and "phy#0" not in block, "wlan1 matched the wlan10 block"


# Current iw releases open each block with "Wiphy phy0"; older ones with "phy#0".
# CI showed the modern format, which the original split did not recognise.
IW_LIST_WIPHY_FORMAT = """Wiphy phy0
\twiphy index: 0
\tmax # scan SSIDs: 4
\tInterfaces:
\t\tInterface wlan0
\t\t\tifindex 3
\t\t\ttype managed
\tFrequencies:
\t\t* 2412 MHz [1] (20.0 dBm)
\t\t* 2437 MHz [6] (20.0 dBm)
\t\t* 2472 MHz [13] (disabled)
Wiphy phy1
\twiphy index: 1
\tmax # scan SSIDs: 4
\tInterfaces:
\t\tInterface wlan1
\t\t\tifindex 4
\t\t\ttype managed
\tFrequencies:
\t\t* 5180 MHz [36] (20.0 dBm)
\t\t* 5745 MHz [149] (20.0 dBm)
"""


def test_phy_block_handles_modern_wiphy_header():
    block = InterfaceManager._phy_block_for(IW_LIST_WIPHY_FORMAT, "wlan1")

    assert "Wiphy phy1" in block
    assert "Wiphy phy0" not in block


def test_phy_block_still_handles_legacy_phy_hash_header():
    block = InterfaceManager._phy_block_for(IW_LIST_TWO_PHYS, "wlan1")

    assert "phy#1" in block and "phy#0" not in block


@pytest.mark.parametrize(
    "iface,expected",
    [("wlan0", [1, 6]), ("wlan1", [36, 149])],
)
def test_supported_channels_with_modern_wiphy_format(monkeypatch, iface, expected):
    """Regression: the CI runner emits 'Wiphy phyN', and channels came back empty."""
    stub_commands(monkeypatch, imod, {("iw", "list"): (0, IW_LIST_WIPHY_FORMAT)})
    im = InterfaceManager(ToolManager(CapabilityRegistry()))

    assert im.get_supported_channels(iface) == expected


def test_phy_block_falls_back_when_only_a_longer_name_exists():
    """No exact match for wlan1, so the documented fallback returns everything."""
    output = (
        "phy#0\n"
        "\tInterface wlan10\n"
        "\t\tFrequencies:\n"
        "\t\t\t* 2412 MHz [1] (20.0 dBm)\n"
    )

    assert InterfaceManager._phy_block_for(output, "wlan1") == output


@pytest.mark.parametrize(
    "iface,expected",
    [("wlan0", [1, 6, 11]), ("wlan1", [36, 149])],
)
def test_supported_channels_are_phy_scoped(monkeypatch, iface, expected):
    stub_commands(monkeypatch, imod, {("iw", "list"): (0, IW_LIST_TWO_PHYS)})
    tm = ToolManager(CapabilityRegistry())
    im = InterfaceManager(tm)

    assert im.get_supported_channels(iface) == expected


def test_disabled_channels_are_excluded(monkeypatch):
    """Channel 13 is listed but marked disabled; it must not be offered."""
    stub_commands(monkeypatch, imod, {("iw", "list"): (0, IW_LIST_TWO_PHYS)})
    im = InterfaceManager(ToolManager(CapabilityRegistry()))

    channels = im.get_supported_channels("wlan0")

    assert 13 not in channels
    assert "2472 MHz [13] (disabled)" in IW_LIST_TWO_PHYS  # it really was present


def test_supported_channels_empty_when_iw_fails(monkeypatch):
    stub_commands(monkeypatch, imod, {("iw", "list"): (1, "", "iw: command failed")})
    im = InterfaceManager(ToolManager(CapabilityRegistry()))

    assert im.get_supported_channels("wlan0") == []


def test_supported_channels_empty_when_iw_missing(monkeypatch):
    stub_commands(monkeypatch, imod, {("iw", "list"): (127, "", "Command not found")})
    im = InterfaceManager(ToolManager(CapabilityRegistry()))

    assert im.get_supported_channels("wlan0") == []


def test_supported_channels_survives_malformed_frequency_lines(monkeypatch):
    output = (
        "phy#0\n"
        "\tInterface wlan0\n"
        "\t\tFrequencies:\n"
        "\t\t\t* 2412 MHz [1] (20.0 dBm)\n"
        "\t\t\t* garbage line without a channel\n"
        "\t\t\t* 2437 MHz [not-a-number] (20.0 dBm)\n"
        "\t\t\t* 2462 MHz [11] (20.0 dBm)\n"
    )
    stub_commands(monkeypatch, imod, {("iw", "list"): (0, output)})
    im = InterfaceManager(ToolManager(CapabilityRegistry()))

    assert im.get_supported_channels("wlan0") == [1, 11]
