"""Offline SAE negotiation analysis using tshark's real dissector."""
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
from ....parsers.sae import parse_sae_tshark_json


class SaeCaptureAnalysisAdapter(ToolAdapterBase):
    """Read an existing capture; never opens an interface or transmits frames."""

    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        read_file = parameters.get("read_file")
        if not isinstance(read_file, str) or not read_file or read_file.startswith("-"):
            raise ValueError("read_file must be an existing capture path, not a command option")
        return [
            "tshark", "-r", read_file, "-T", "json",
            "-Y", "wlan.fixed.auth_alg == 3",
        ]

    def parse_output(
        self,
        raw_output: str,
        error_output: str,
        exit_code: int,
        parameters: Dict[str, Any],
        interface: str | None,
    ) -> List[Evidence]:
        combined = raw_output or error_output
        if exit_code != 0 and not combined.strip():
            return []
        issues: List[str] = []
        parsed = parse_sae_tshark_json(combined, issues=issues)
        self.parse_warnings.extend(issues)
        if not parsed:
            return []
        return [
            Evidence.from_tool_output(
                tool_name="tshark",
                capability="sae_capture_analysis",
                evidence_type=EvidenceType.HANDSHAKE,
                raw_output=raw_output,
                parsed_data=parsed[0],
                parameters=parameters,
                interface=None,
                confidence=ConfidenceLevel.HIGH,
                execution_id=self.execution_id,
                raw_command="tshark -r <capture> -T json -Y wlan.fixed.auth_alg == 3",
            )
        ]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        read_file = parameters.get("read_file")
        if not isinstance(read_file, str) or not read_file.strip():
            return False, ["read_file is required for offline SAE analysis"]
        return True, []


METADATA = ToolCapabilityMetadata(
    name="sae_capture_analysis",
    display_name="tshark - Offline SAE Negotiation Analysis",
    category=CapabilityCategory.WPA_ASSESSMENT,
    description="Extract explicitly decoded SAE groups and authentication state from an existing capture",
    tool_binary="tshark",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["read_file"],
    outputs=["sae_groups_observed", "sae_commit_count", "sae_confirm_count"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.OFFLINE_ANALYSIS,
        persistent=False,
        estimated_duration_seconds=10,
        invasive=False,
        requires_authorization=False,
    ),
    failure_conditions=["capture_unreadable", "tool_not_found", "dissector_missing"],
    tags=["wpa3", "sae", "dragonblood", "offline", "tshark"],
)

ADAPTER_CLASS = SaeCaptureAnalysisAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
