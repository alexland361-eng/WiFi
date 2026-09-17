"""Tests for executor."""
from wifi_framework.core.models.assessment_state import AssessmentState
from wifi_framework.core.models.scope import AssessmentScope
from wifi_framework.core.execution.registry import CapabilityRegistry
from wifi_framework.core.execution.executor import CapabilityExecutor
from wifi_framework.core.models.capability import ToolCapabilityMetadata, CapabilityCategory, CapabilityRequirements, OperatingSystem, OperationalProperties, OperationalMode
from wifi_framework.core.execution.adapter_base import ToolAdapterBase
from typing import List
from wifi_framework.core.models.evidence import Evidence, EvidenceType


class EchoAdapter(ToolAdapterBase):
    def build_command(self, interface, parameters) -> List[str]:
        return ["echo", parameters.get("message", "hello")]

    def parse_output(self, raw_output, error_output, exit_code, parameters, interface) -> List[Evidence]:
        ev = Evidence.from_tool_output(
            tool_name="echo",
            capability="test",
            evidence_type=EvidenceType.GENERIC,
            raw_output=raw_output,
            parsed_data={"message": raw_output.strip()},
            parameters=parameters,
        )
        return [ev]


def test_executor_with_echo():
    registry = CapabilityRegistry()

    metadata = ToolCapabilityMetadata(
        name="echo_test",
        display_name="Echo Test",
        category=CapabilityCategory.WIRELESS_INTERFACE,
        description="Test",
        tool_binary="echo",
        requirements=CapabilityRequirements(operating_systems=[OperatingSystem.LINUX]),
        inputs=["optional_message"],
        outputs=["generic"],
        operational_properties=OperationalProperties(mode=OperationalMode.PASSIVE_OBSERVATION),
    )

    registry.register(metadata, EchoAdapter)

    scope = AssessmentScope()
    state = AssessmentState(scope=scope)

    executor = CapabilityExecutor(registry, state)

    result = executor.execute("echo_test", parameters={"message": "test123"}, timeout=5, state=state)

    assert result.success
    assert len(result.evidences) == 1
    assert result.evidences[0].parsed_data["message"] == "test123"
    assert len(state.evidences) == 1
    assert len(state.execution_history) == 1
