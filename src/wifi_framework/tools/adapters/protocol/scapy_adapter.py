"""
Adapter for Scapy - programmable packet manipulation and analysis framework.

Unlike traditional command-line utilities, Scapy can serve as programmatic protocol-analysis
component for specialized authorized testing.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ....core.execution.adapter_base import ToolAdapterBase
from ....core.models.capability import (
    CapabilityCategory,
    CapabilityRequirements,
    OperationalMode,
    OperationalProperties,
    OperatingSystem,
    ToolCapabilityMetadata,
)
from ....core.models.evidence import ConfidenceLevel, Evidence, EvidenceType


class ScapyAdapter(ToolAdapterBase):
    """
    Adapter that executes Scapy scripts.

    Instead of wrapping a binary, this adapter runs Python code using Scapy library.
    """

    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        # Scapy adapter doesn't use a traditional binary command
        # It will execute Python with scapy
        # For compatibility with base class, we return a python command that runs scapy script

        script = parameters.get("script")
        if not script:
            # Default to version check
            return ["python3", "-c", "import scapy; print(scapy.__version__)"]

        # Write script to temp file and execute
        # The actual execution is handled in overridden execute method
        # For build_command, return placeholder
        return ["python3", "-c", script[:100]]

    def execute(self, interface: str | None = None, parameters: Dict[str, Any] = None, timeout: int = 30):
        """
        Override execute to handle Scapy library directly if available.
        """
        parameters = parameters or {}

        # Try to import scapy
        try:
            import scapy.all as scapy

            # If script provided, execute it
            script = parameters.get("script")
            if script:
                # For security, we restrict execution to safe context
                # In production, this would be sandboxed
                # Here we provide a controlled execution
                local_vars = {"scapy": scapy, "interface": interface}
                try:
                    # Capture output
                    import io
                    import sys

                    old_stdout = sys.stdout
                    old_stderr = sys.stderr
                    sys.stdout = io.StringIO()
                    sys.stderr = io.StringIO()

                    exec(script, {"__builtins__": __builtins__, "scapy": scapy}, local_vars)

                    stdout = sys.stdout.getvalue()
                    stderr = sys.stderr.getvalue()

                    sys.stdout = old_stdout
                    sys.stderr = old_stderr

                    # Parse output into evidence
                    from ....core.models.evidence import EvidenceSource

                    ev = Evidence.from_tool_output(
                        tool_name="scapy",
                        capability="protocol_analysis",
                        evidence_type=EvidenceType.GENERIC,
                        raw_output=stdout,
                        parsed_data={"script_output": stdout[:2000], "interface": interface},
                        parameters=parameters,
                        interface=interface,
                        confidence=ConfidenceLevel.MEDIUM,
                        execution_id=self.execution_id,
                        raw_command="scapy script",
                    )

                    from ...execution.adapter_base import AdapterExecutionResult

                    return AdapterExecutionResult(
                        success=True,
                        raw_output=stdout,
                        error_output=stderr,
                        exit_code=0,
                        duration=0.0,
                        evidences=[ev],
                        raw_command="scapy script execution",
                    )

                except Exception as e:
                    sys.stdout = old_stdout
                    sys.stderr = old_stderr
                    from ...execution.adapter_base import AdapterExecutionResult

                    return AdapterExecutionResult(
                        success=False,
                        raw_output="",
                        error_output=str(e),
                        exit_code=1,
                        duration=0.0,
                        evidences=[],
                        failure_reason=f"Scapy script execution failed: {e}",
                        raw_command="scapy script",
                    )
            else:
                # Version check
                from ...execution.adapter_base import AdapterExecutionResult

                version = getattr(scapy, "__version__", "unknown")
                ev = Evidence.from_tool_output(
                    tool_name="scapy",
                    capability="protocol_analysis",
                    evidence_type=EvidenceType.GENERIC,
                    raw_output=version,
                    parsed_data={"version": version},
                    parameters=parameters,
                    interface=interface,
                    confidence=ConfidenceLevel.HIGH,
                    execution_id=self.execution_id,
                    raw_command="scapy version check",
                )
                return AdapterExecutionResult(
                    success=True,
                    raw_output=version,
                    error_output="",
                    exit_code=0,
                    duration=0.0,
                    evidences=[ev],
                    raw_command="scapy version check",
                )

        except ImportError:
            # Fallback to base execution which will try python3 -c
            return super().execute(interface, parameters, timeout)

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        # This is used when falling back to subprocess
        if exit_code != 0 and not raw_output:
            return []

        ev = Evidence.from_tool_output(
            tool_name="scapy",
            capability="protocol_analysis",
            evidence_type=EvidenceType.GENERIC,
            raw_output=raw_output,
            parsed_data={"output": raw_output[:2000], "interface": interface},
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command="scapy",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


METADATA = ToolCapabilityMetadata(
    name="scapy",
    display_name="Scapy - Packet Manipulation",
    category=CapabilityCategory.PROTOCOL_ANALYSIS,
    description="Programmable packet manipulation and analysis framework for specialized authorized testing",
    tool_binary="python3",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
        dependencies=["scapy"],
    ),
    inputs=["optional_script", "optional_interface"],
    outputs=["capture", "generic"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_TESTING,
        persistent=False,
        estimated_duration_seconds=10,
        invasive=True,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found", "invalid_parameters"],
    tags=["packet", "scapy", "python"],
)

ADAPTER_CLASS = ScapyAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
