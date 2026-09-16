"""Tests for adapters."""
from wifi_framework.core.execution.registry import CapabilityRegistry
from wifi_framework.tools.registry_loader import load_all_adapters


def test_registry_loading():
    registry = CapabilityRegistry()
    load_all_adapters(registry)

    # Should have many capabilities
    caps = registry.list_capabilities()
    assert len(caps) >= 20, f"Expected at least 20 capabilities, got {len(caps)}: {caps}"

    # Check some expected capabilities exist
    expected = ["iw_dev", "airodump-ng", "wash", "tshark", "nmap", "reaver"]
    for exp in expected:
        assert exp in caps, f"Expected capability {exp} not found"


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
