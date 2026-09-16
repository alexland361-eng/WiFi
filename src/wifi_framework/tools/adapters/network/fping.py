"""
Adapter for fping - efficient host reachability testing.
"""
from __future__ import annotations

import re
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


class FpingAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        cmd = ["fping"]

        # Options
        if parameters.get("count"):
            cmd.extend(["-c", str(parameters["count"])])

        if parameters.get("retries"):
            cmd.extend(["-r", str(parameters["retries"])])

        # Generate file
        if parameters.get("generate_file"):
            cmd.extend(["-f", parameters["generate_file"]])

        # Target
        target = parameters.get("target") or parameters.get("network")
        if target:
            # fping can take network in various formats
            if "/" in target or "-" in target:
                # For range, use -g
                cmd.extend(["-g", target])
            else:
                cmd.append(target)
        else:
            cmd.append("--help")

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output
        evidences = []

        # fping output:
        # 192.168.1.1 is alive
        # 192.168.1.2 is unreachable

        for line in combined.splitlines():
            line = line.strip()
            m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+is\s+alive", line)
            if m:
                ip = m.group(1)
                ev = Evidence.from_tool_output(
                    tool_name="fping",
                    capability="network_discovery",
                    evidence_type=EvidenceType.NETWORK_HOST,
                    raw_output=combined,
                    parsed_data={"ip": ip, "status": "up", "alive": True},
                    parameters=parameters,
                    interface=interface,
                    confidence=ConfidenceLevel.HIGH,
                    execution_id=self.execution_id,
                    raw_command="fping",
                )
                evidences.append(ev)
            else:
                m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+is\s+unreachable", line)
                if m:
                    ip = m.group(1)
                    ev = Evidence.from_tool_output(
                        tool_name="fping",
                        capability="network_discovery",
                        evidence_type=EvidenceType.NETWORK_HOST,
                        raw_output=combined,
                        parsed_data={"ip": ip, "status": "down", "alive": False},
                        parameters=parameters,
                        interface=interface,
                        confidence=ConfidenceLevel.MEDIUM,
                        execution_id=self.execution_id,
                        raw_command="fping",
                    )
                    evidences.append(ev)

        return evidences

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


METADATA = ToolCapabilityMetadata(
    name="fping",
    display_name="fping - Host Reachability",
    category=CapabilityCategory.NETWORK_DISCOVERY,
    description="Efficient host reachability testing",
    tool_binary="fping",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["optional_target", "optional_count"],
    outputs=["network_hosts"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=10,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found", "invalid_parameters"],
    tags=["ping", "reachability"],
)

ADAPTER_CLASS = FpingAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
