"""
Adapter for dig - low-level DNS query and analysis.
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


class DigAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        cmd = ["dig"]

        # Server
        if parameters.get("server"):
            cmd.append(f"@{parameters['server']}")

        # Domain
        domain = parameters.get("domain") or parameters.get("target")
        if domain:
            cmd.append(domain)
        else:
            raise ValueError("Domain required for dig")

        # Record type
        if parameters.get("record_type"):
            cmd.append(parameters["record_type"])

        # Additional options
        if parameters.get("short"):
            cmd.append("+short")

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed = {
            "domain": parameters.get("domain") or parameters.get("target"),
            "record_type": parameters.get("record_type", "A"),
        }

        # Parse ANSWER section
        answers = []
        in_answer = False
        for line in combined.splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                if "ANSWER SECTION" in line:
                    in_answer = True
                continue
            if in_answer:
                if line.startswith(";") or not line:
                    if "ANSWER SECTION" not in line:
                        # End of answer? Actually continue until blank or next section
                        pass
                # Typical answer: example.com. 300 IN A 93.184.216.34
                parts = line.split()
                if len(parts) >= 5:
                    answers.append(
                        {
                            "name": parts[0],
                            "ttl": parts[1],
                            "class": parts[2],
                            "type": parts[3],
                            "value": " ".join(parts[4:]),
                        }
                    )

        parsed["answers"] = answers

        # If +short, parse directly
        if parameters.get("short"):
            ips = []
            for line in combined.splitlines():
                line = line.strip()
                if re.match(r"\d+\.\d+\.\d+\.\d+", line):
                    ips.append(line)
            parsed["ips"] = ips

        ev = Evidence.from_tool_output(
            tool_name="dig",
            capability="network_discovery",
            evidence_type=EvidenceType.DNS,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.HIGH,
            execution_id=self.execution_id,
            raw_command=f"dig {parsed['domain']}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("domain") and not parameters.get("target"):
            return False, ["Domain required"]
        return True, []


METADATA = ToolCapabilityMetadata(
    name="dig",
    display_name="dig - DNS Query",
    category=CapabilityCategory.NETWORK_DISCOVERY,
    description="Low-level DNS query and analysis utility",
    tool_binary="dig",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["domain", "optional_record_type", "optional_server"],
    outputs=["dns_observation"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=5,
        invasive=False,
        requires_authorization=False,
    ),
    failure_conditions=["tool_not_found", "invalid_parameters"],
    tags=["dns", "enumeration"],
)

ADAPTER_CLASS = DigAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
