"""
Vulnerability assessment adapters: Nuclei, Nikto, Greenbone/OpenVAS

Deep research:
  Nuclei: https://github.com/projectdiscovery/nuclei, template-based vuln identification
    nuclei -u http://192.168.1.1 -t /path/to/templates/ -o output.txt
  Nikto: https://cirt.net/Nikto2, web-server assessment
    nikto -h http://192.168.1.1 -o /tmp/nikto.txt
  OpenVAS: https://www.greenbone.github.io/docs/latest/, broader vuln assessment
    gvm-cli ...

Philosophy: Should NOT be launched merely because installed. Orchestrator selects only when world model indicates prerequisites and assessment purpose satisfied.

Prerequisites: HTTP service discovered, in vulnerability assessment phase, authorized scope
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


class NucleiAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        target = parameters.get("target") or parameters.get("url") or parameters.get("host")
        if not target:
            raise ValueError("Target required for nuclei")

        cmd = ["nuclei", "-u", target]

        if parameters.get("templates"):
            cmd.extend(["-t", parameters["templates"]])

        if parameters.get("output"):
            cmd.extend(["-o", parameters["output"]])

        if parameters.get("severity"):
            cmd.extend(["-severity", parameters["severity"]])

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed = {
            "target": parameters.get("target") or parameters.get("url") or parameters.get("host"),
            "vulnerabilities": [],
        }

        # Parse nuclei output: [severity] [template] [url] [info]
        for line in combined.splitlines():
            # Example: [medium] [http-missing-security-headers] [http://192.168.1.1] [header]
            m = re.search(r"\[(info|low|medium|high|critical)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]", line)
            if m:
                severity = m.group(1)
                template = m.group(2)
                url = m.group(3)
                parsed["vulnerabilities"].append(
                    {"severity": severity, "template": template, "url": url, "raw": line.strip()}
                )

        evidences = []
        for vuln in parsed["vulnerabilities"]:
            ev = Evidence.from_tool_output(
                tool_name="nuclei",
                capability="vulnerability_assessment",
                evidence_type=EvidenceType.VULNERABILITY,
                raw_output=combined,
                parsed_data=vuln,
                parameters=parameters,
                interface=interface,
                confidence=ConfidenceLevel.HIGH if vuln["severity"] in ["high", "critical"] else ConfidenceLevel.MEDIUM,
                execution_id=self.execution_id,
                raw_command=f"nuclei -u {parsed['target']}",
            )
            evidences.append(ev)

        if not evidences and combined.strip():
            # Generic evidence if no vulns parsed but output exists
            ev = Evidence.from_tool_output(
                tool_name="nuclei",
                capability="vulnerability_assessment",
                evidence_type=EvidenceType.GENERIC,
                raw_output=combined,
                parsed_data=parsed,
                parameters=parameters,
                interface=interface,
                confidence=ConfidenceLevel.LOW,
                execution_id=self.execution_id,
                raw_command=f"nuclei -u {parsed['target']}",
            )
            evidences.append(ev)

        return evidences

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("target") and not parameters.get("url") and not parameters.get("host"):
            return False, ["Target required"]
        return True, []


class NiktoAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        target = parameters.get("target") or parameters.get("host") or parameters.get("url")
        if not target:
            raise ValueError("Target required for nikto")

        cmd = ["nikto", "-h", target]

        if parameters.get("output"):
            cmd.extend(["-o", parameters["output"]])

        if parameters.get("port"):
            cmd.extend(["-p", str(parameters["port"])])

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed = {
            "target": parameters.get("target") or parameters.get("host") or parameters.get("url"),
            "findings": [],
        }

        # Parse nikto output: lines with OSVDB, etc.
        for line in combined.splitlines():
            if "OSVDB" in line or "Nikto" in line or "+" in line[:2]:
                parsed["findings"].append(line.strip())

        evidences = []
        for finding in parsed["findings"][:20]:  # Limit
            ev = Evidence.from_tool_output(
                tool_name="nikto",
                capability="vulnerability_assessment",
                evidence_type=EvidenceType.VULNERABILITY,
                raw_output=combined,
                parsed_data={"target": parsed["target"], "finding": finding},
                parameters=parameters,
                interface=interface,
                confidence=ConfidenceLevel.MEDIUM,
                execution_id=self.execution_id,
                raw_command=f"nikto -h {parsed['target']}",
            )
            evidences.append(ev)

        if not evidences:
            ev = Evidence.from_tool_output(
                tool_name="nikto",
                capability="vulnerability_assessment",
                evidence_type=EvidenceType.GENERIC,
                raw_output=combined,
                parsed_data=parsed,
                parameters=parameters,
                interface=interface,
                confidence=ConfidenceLevel.LOW,
                execution_id=self.execution_id,
                raw_command=f"nikto -h {parsed['target']}",
            )
            evidences.append(ev)

        return evidences

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("target") and not parameters.get("host") and not parameters.get("url"):
            return False, ["Target required"]
        return True, []


NUCLEI_METADATA = ToolCapabilityMetadata(
    name="nuclei",
    display_name="Nuclei - Template-Based Vuln Scanner",
    category=CapabilityCategory.VULNERABILITY_ASSESSMENT,
    description="Template-based vulnerability identification for applicable network/web targets - only when prerequisites satisfied",
    tool_binary="nuclei",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["target", "optional_templates", "optional_severity"],
    outputs=["vulnerability"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=60,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found", "invalid_parameters"],
    tags=["vuln", "web", "template"],
    references=["https://github.com/projectdiscovery/nuclei"],
)

NIKTO_METADATA = ToolCapabilityMetadata(
    name="nikto",
    display_name="Nikto - Web Server Assessment",
    category=CapabilityCategory.VULNERABILITY_ASSESSMENT,
    description="Web-server assessment where HTTP service has been legitimately discovered",
    tool_binary="nikto",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["target", "optional_port", "optional_output"],
    outputs=["vulnerability"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=60,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found"],
    tags=["vuln", "web", "nikto"],
    references=["https://cirt.net/Nikto2"],
)


def register(registry):
    registry.register(NUCLEI_METADATA, NucleiAdapter)
    registry.register(NIKTO_METADATA, NiktoAdapter)
