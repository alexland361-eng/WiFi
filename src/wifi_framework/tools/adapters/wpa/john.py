"""
Adapter for john - John the Ripper credential assessment.
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


class JohnAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        # John can work on various formats
        cmd = ["john"]

        if parameters.get("wordlist"):
            cmd.extend(["--wordlist", parameters["wordlist"]])

        if parameters.get("format"):
            cmd.extend(["--format", parameters["format"]])

        if parameters.get("session"):
            cmd.extend(["--session", parameters["session"]])

        hash_file = parameters.get("hash_file") or parameters.get("input_file")
        if hash_file:
            cmd.append(hash_file)
        else:
            # If no hash file, show help for availability check
            cmd.append("--help")

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed = {
            "hash_file": parameters.get("hash_file") or parameters.get("input_file"),
            "success": False,
        }

        # Parse cracked passwords
        # John output: "password (user)" or "0g 0:00:00:00 0g/s ..."
        cracked = []
        for line in combined.splitlines():
            # Look for lines with password
            if "(" in line and ")" in line:
                # Possible cracked line
                m = re.search(r"^\s*(\S+)\s+\((\S+)\)", line)
                if m:
                    cracked.append({"password": m.group(1), "user": m.group(2), "raw": line.strip()})

        if cracked:
            parsed["cracked"] = cracked
            parsed["success"] = True
            parsed["cracked_count"] = len(cracked)

        ev = Evidence.from_tool_output(
            tool_name="john",
            capability="credential_assessment",
            evidence_type=EvidenceType.CREDENTIAL,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.HIGH if parsed.get("success") else ConfidenceLevel.LOW,
            execution_id=self.execution_id,
            raw_command="john",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


METADATA = ToolCapabilityMetadata(
    name="john",
    display_name="John the Ripper - Credential Assessment",
    category=CapabilityCategory.CREDENTIAL_ASSESSMENT,
    description="John the Ripper for authorized offline credential-strength assessment",
    tool_binary="john",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["optional_hash_file", "optional_wordlist", "optional_format"],
    outputs=["credential_observation"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.OFFLINE_ANALYSIS,
        persistent=False,
        estimated_duration_seconds=120,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found", "invalid_parameters"],
    tags=["cracking", "offline", "john"],
)

ADAPTER_CLASS = JohnAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
