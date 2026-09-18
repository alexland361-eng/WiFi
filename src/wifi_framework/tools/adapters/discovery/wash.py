"""
Adapter for `wash` - WPS discovery.
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
from ....core.models.evidence import Evidence
from ....parsers.wash import wash_to_evidences


class WashAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        if not interface:
            raise ValueError("Interface required for wash")

        cmd = ["wash", "-i", interface]

        # Channel
        if parameters.get("channel"):
            cmd.extend(["-c", str(parameters["channel"])])

        # Survey mode (passive)
        if parameters.get("survey"):
            cmd.append("-s")

        # JSON output if supported
        if parameters.get("json"):
            cmd.append("-j")

        # Ignore FCS errors
        if parameters.get("ignore_fcs"):
            cmd.append("-C")

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output
        if exit_code != 0 and not combined.strip():
            return []

        # Same wiring as the nmap and tshark adapters: the parser reports what it could not
        # use, and those reports travel on ExecutionResult.parse_warnings to the evidence
        # engine and the audit trail. Without this a BSSID the parser rejected - a value the
        # canonical MAC rule refuses, so one that could never match an authorized scope
        # entry - would vanish with no trace of why.
        issues: List[str] = []
        evidences = wash_to_evidences(
            combined, interface=interface, execution_id=self.execution_id, issues=issues
        )
        self.parse_warnings.extend(issues)
        return evidences

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        errors = []
        if "channel" in parameters and parameters["channel"] is not None:
            try:
                ch = int(parameters["channel"])
                if not 1 <= ch <= 196:
                    errors.append(f"Invalid channel {ch}")
            except (ValueError, TypeError):
                errors.append("Channel must be integer")
        return (False, errors) if errors else (True, [])


METADATA = ToolCapabilityMetadata(
    name="wash",
    display_name="wash - WPS Discovery",
    category=CapabilityCategory.WPS_DISCOVERY,
    description="Authorized discovery and assessment of WPS-enabled wireless networks",
    tool_binary="wash",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=True,
        interface_capabilities=["monitor_mode"],
        privileges=["root"],
    ),
    inputs=["interface", "optional_channel", "optional_survey"],
    outputs=["wps_observations", "access_points"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=True,
        estimated_duration_seconds=20,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=[
        "interface_unavailable",
        "unsupported_driver",
        "insufficient_privileges",
        "timeout",
    ],
    tags=["wps", "discovery"],
)

ADAPTER_CLASS = WashAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
