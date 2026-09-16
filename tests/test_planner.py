"""Tests for planning."""
from wifi_framework.core.models.assessment_state import AssessmentState
from wifi_framework.core.models.scope import AssessmentScope
from wifi_framework.core.planning.uncertainty import UncertaintyIdentifier
from wifi_framework.core.execution.registry import CapabilityRegistry
from wifi_framework.core.models.capability import ToolCapabilityMetadata, CapabilityCategory, CapabilityRequirements, OperatingSystem, OperationalProperties, OperationalMode


def test_uncertainty_identifier():
    scope = AssessmentScope()
    state = AssessmentState(scope=scope)

    identifier = UncertaintyIdentifier()
    uncertainties = identifier.identify(state)

    # Should have interface discovery uncertainty when no interfaces
    assert any(u["type"] == "interface_discovery" for u in uncertainties)
    # Should have wireless observation uncertainty when no APs
    assert any(u["type"] == "wireless_observation" for u in uncertainties)


def test_uncertainty_priority():
    scope = AssessmentScope()
    state = AssessmentState(scope=scope)

    identifier = UncertaintyIdentifier()
    uncertainties = identifier.identify(state)

    # Should be sorted by priority descending
    priorities = [u["priority"] for u in uncertainties]
    assert priorities == sorted(priorities, reverse=True)


def test_action_selector_scoring():
    from wifi_framework.core.planning.action_selector import ActionSelector

    registry = CapabilityRegistry()

    # Register dummy capability
    metadata = ToolCapabilityMetadata(
        name="test_cap",
        display_name="Test",
        category=CapabilityCategory.WIRELESS_OBSERVATION,
        description="Test",
        tool_binary="echo",
        requirements=CapabilityRequirements(operating_systems=[OperatingSystem.LINUX]),
        inputs=["interface"],
        outputs=["access_points"],
        operational_properties=OperationalProperties(mode=OperationalMode.PASSIVE_OBSERVATION, invasive=False),
    )

    from wifi_framework.core.execution.adapter_base import ToolAdapterBase
    from typing import List, Dict, Any
    from wifi_framework.core.models.evidence import Evidence

    class DummyAdapter(ToolAdapterBase):
        def build_command(self, interface, parameters) -> List[str]:
            return ["echo", "test"]

        def parse_output(self, raw_output, error_output, exit_code, parameters, interface) -> List[Evidence]:
            return []

    registry.register(metadata, DummyAdapter)

    selector = ActionSelector(registry)

    scope = AssessmentScope()
    state = AssessmentState(scope=scope)

    uncertainty = {
        "type": "wireless_observation",
        "priority": 8,
        "required_capabilities": ["test_cap"],
    }

    score, reason = selector.score_capability(metadata, uncertainty, state)
    assert score > 0
    assert "Directly addresses" in reason
