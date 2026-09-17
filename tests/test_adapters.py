"""Tests for adapters."""
import pytest

from wifi_framework.core.execution.registry import CapabilityRegistry
from wifi_framework.tools.registry_loader import load_all_adapters


def test_registry_loading():
    registry = CapabilityRegistry()
    load_all_adapters(registry)

    # Should have many capabilities - after deep research and tool handling we have 58 covering full Kali toolchain
    caps = registry.list_capabilities()
    assert len(caps) >= 50, f"Expected at least 50 capabilities after deep research and tool management, got {len(caps)}: {caps}"

    # Check some expected capabilities exist - covering all categories from spec
    expected = [
        "iw_dev",
        "iw_list",
        "airmon-ng",
        "aireplay-ng",
        "airodump-ng",
        "aircrack-ng",
        "airdecap-ng",
        "airbase-ng",
        "airserv-ng",
        "packetforge-ng",
        "wpaclean",
        "airdecloak-ng",
        "wash",
        "tshark",
        "tcpdump",
        "dumpcap",
        "termshark",
        "nmap",
        "reaver",
        "bully",
        "pixiewps",
        "hcxdumptool",
        "hcxpcapngtool",
        "hashcat",
        "nuclei",
        "nikto",
        "openvas",
        "curl",
        "wget",
        "ftp",
        "ldapsearch",
        "rpcclient",
        "smbclient",
        "smbmap",
        "enum4linux-ng",
        "nbtscan",
        "snmpwalk",
        "mitmproxy",
        "macchanger",
        "bettercap",
        "scapy",
        "metasploit",
        "impacket",
        "responder",
        "dnsenum",
        "dnsrecon",
    ]
    for exp in expected:
        assert exp in caps, f"Expected capability {exp} not found after deep research and tool management implementation"


def test_adapter_metadata():
    registry = CapabilityRegistry()
    load_all_adapters(registry)

    # Check metadata for airodump-ng
    meta = registry.get_metadata("airodump-ng")
    assert meta is not None
    assert meta.tool_binary == "airodump-ng"
    assert meta.requirements.interface_required is True
    assert "monitor_mode" in meta.requirements.interface_capabilities
    assert "access_points" in meta.outputs


def test_adapter_availability_check():
    registry = CapabilityRegistry()
    load_all_adapters(registry)

    # Check availability for a tool that likely exists (echo is used in test adapter, but real tools may not exist in sandbox)
    # We test the checker logic
    from wifi_framework.core.execution.capability_checker import CapabilityChecker

    checker = CapabilityChecker()

    # Create dummy metadata for echo (should exist)
    from wifi_framework.core.models.capability import ToolCapabilityMetadata, CapabilityCategory, CapabilityRequirements, OperatingSystem

    meta = ToolCapabilityMetadata(
        name="echo_test",
        display_name="Echo",
        category=CapabilityCategory.WIRELESS_INTERFACE,
        description="Test",
        tool_binary="echo",
        requirements=CapabilityRequirements(operating_systems=[OperatingSystem.LINUX]),
    )

    available, reason, details = checker.check(meta)
    assert available, f"echo should be available, got {reason}"


# --------------------------------------------- declared-input validation
#
# `ToolAdapterBase.validate_parameters` computed the capability's required inputs and
# then discarded them, delegating to a hook whose default accepts everything. A method
# named validate_parameters validated nothing, so an adapter invoked without an input it
# cannot work without built a command line missing that argument and the tool's own
# complaint came back as a runtime failure instead of a refusal naming the missing input.


def _registry():
    registry = CapabilityRegistry()
    return load_all_adapters(registry)


def test_a_missing_required_input_is_refused_by_name():
    adapter = _registry().get_adapter_instance("nmap")
    assert "target" in adapter.metadata.inputs

    ok, errors = adapter.validate_parameters({})
    assert ok is False
    # The nmap adapter also checks for a target in its own hook, so the refusal names it
    # twice - once from the declared-input check and once from the adapter. Redundant but
    # consistent, and both layers reporting is the behaviour the aireplay test below pins.
    assert "Missing required parameter: target" in errors, errors
    assert all("target" in error.lower() for error in errors), errors


def test_a_capability_with_no_required_inputs_accepts_an_empty_parameter_set():
    """`iw_dev` declares only optional inputs, so an empty set is a valid invocation -
    enforcement must not invent requirements the capability model does not state."""
    adapter = _registry().get_adapter_instance("iw_dev")
    assert all(name.startswith("optional_") for name in adapter.metadata.inputs)

    ok, errors = adapter.validate_parameters({})
    assert ok is True
    assert errors == []


def test_an_optional_input_is_not_required():
    adapter = _registry().get_adapter_instance("airodump-ng")
    assert "optional_channel" in adapter.metadata.inputs

    ok, errors = adapter.validate_parameters({}, "wlan0mon")
    assert ok is True, errors


@pytest.mark.parametrize("name", ["airodump-ng", "horst", "macchanger"])
def test_an_interface_argument_satisfies_a_declared_interface_input(name):
    """`interface` reaches `execute` as its own argument rather than as a key in
    `parameters`. Checking `parameters` alone would refuse every normal invocation of
    the capabilities that declare an interface, which is why the computed list was left
    unused rather than wired up naively."""
    adapter = _registry().get_adapter_instance(name)
    assert "interface" in adapter.metadata.inputs

    ok, errors = adapter.validate_parameters({}, "wlan0mon")
    assert ok is True, f"{name}: {errors}"


def test_an_interface_inside_parameters_also_satisfies_it():
    adapter = _registry().get_adapter_instance("horst")

    ok, errors = adapter.validate_parameters({"interface": "wlan0mon"})
    assert ok is True, errors


def test_a_complete_parameter_set_passes():
    adapter = _registry().get_adapter_instance("aireplay-ng")
    assert set(["interface", "action"]) <= set(adapter.metadata.inputs)

    # aireplay-ng's own hook requires a BSSID for a deauth action, on top of the
    # declared inputs - so "complete" means both layers satisfied.
    ok, errors = adapter.validate_parameters(
        {"action": "deauth", "bssid": "AA:BB:CC:DD:EE:FF"}, "wlan0mon"
    )
    assert ok is True, errors


def test_adapter_specific_checks_run_alongside_declared_input_checks():
    """Both layers report, rather than one short-circuiting the other: an operator
    fixing the missing input should see the invalid value in the same refusal."""
    adapter = _registry().get_adapter_instance("airodump-ng")

    ok, errors = adapter.validate_parameters({"channel": 999})
    assert ok is False
    assert any("interface" in error for error in errors), errors
    assert any("channel" in error.lower() for error in errors), errors
    assert len(errors) == 2, errors


def test_an_invalid_value_with_every_required_input_present_is_still_refused():
    adapter = _registry().get_adapter_instance("airodump-ng")

    ok, errors = adapter.validate_parameters({"channel": 999}, "wlan0mon")
    assert ok is False
    assert len(errors) == 1
    assert "999" in errors[0]


def test_execute_refuses_before_invoking_the_tool():
    """The check has to run before the tool does, or it saves nothing."""
    adapter = _registry().get_adapter_instance("nmap")

    result = adapter.execute(interface=None, parameters={}, timeout=5)

    assert result.success is False
    assert "Parameter validation failed" in (result.failure_reason or "")
    assert "Missing required parameter: target" in (result.failure_reason or "")
    assert not result.raw_command, "a command line was built for an invocation missing its target"
