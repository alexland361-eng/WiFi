"""
Adapter for bettercap - broad network assessment framework.

Because it provides many overlapping functions, orchestrator should expose individual
capabilities rather than treating Bettercap as opaque "run everything" operation.
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


class BettercapAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        # Bettercap can run with various caplets and commands
        cmd = ["bettercap"]

        if interface:
            cmd.extend(["-iface", interface])

        # Caplet
        if parameters.get("caplet"):
            cmd.extend(["-caplet", parameters["caplet"]])

        # Commands to evaluate
        if parameters.get("eval"):
            cmd.extend(["-eval", parameters["eval"]])

        # If no specific eval, just check version/capabilities
        if len(cmd) == 1 or (len(cmd) == 3 and interface):
            cmd.append("--help")

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed = {
            "interface": interface,
            "caplet": parameters.get("caplet"),
            "eval": parameters.get("eval"),
        }

        ev = Evidence.from_tool_output(
            tool_name="bettercap",
            capability="protocol_analysis",
            evidence_type=EvidenceType.GENERIC,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.LOW,
            execution_id=self.execution_id,
            raw_command="bettercap",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


METADATA = ToolCapabilityMetadata(
    name="bettercap",
    display_name="bettercap - Network Assessment Framework",
    category=CapabilityCategory.PROTOCOL_ANALYSIS,
    description="Broad network assessment framework containing wireless and network reconnaissance capabilities",
    tool_binary="bettercap",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=["root"],
    ),
    inputs=["optional_interface", "optional_caplet", "optional_eval"],
    outputs=["network_hosts", "access_points"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=20,
        invasive=True,
        requires_authorization=True,
    ),
    failure_conditions=["interface_unavailable", "insufficient_privileges", "tool_not_found"],
    tags=["framework", "mitm", "recon"],
)

ADAPTER_CLASS = BettercapAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
