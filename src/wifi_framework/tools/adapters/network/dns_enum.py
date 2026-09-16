"""
Adapters for DNS enumeration: dnsenum, dnsrecon, dig (enhanced)

Deep research:
  dnsenum: https://github.com/fwaeytens/dnsenum, https://www.kali.org/tools/dnsenum/
  dnsrecon: https://github.com/darkoperator/dnsrecon, https://www.kali.org/tools/dnsrecon/
  Real usage:
    dnsenum --dnsserver 8.8.8.8 --enum -f wordlist.txt example.com
    dnsrecon -d example.com -t std -n 8.8.8.8
    dig @8.8.8.8 example.com AXFR
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


class DnsenumAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        domain = parameters.get("domain") or parameters.get("target")
        if not domain:
            raise ValueError("Domain required for dnsenum")

        cmd = ["dnsenum"]

        if parameters.get("dnsserver"):
            cmd.extend(["--dnsserver", parameters["dnsserver"]])

        if parameters.get("enum"):
            cmd.append("--enum")

        if parameters.get("wordlist"):
            cmd.extend(["-f", parameters["wordlist"]])

        # Additional options
        if parameters.get("scrap"):
            cmd.extend(["-s", str(parameters["scrap"])])

        if parameters.get("whois"):
            cmd.append("--whois")

        cmd.append(domain)
        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed = {
            "domain": parameters.get("domain") or parameters.get("target"),
            "hosts": [],
            "ips": [],
            "nameservers": [],
        }

        # Parse hosts
        # Example: "host.example.com. 300 IN A 93.184.216.34"
        for line in combined.splitlines():
            # Look for A records
            m = re.search(r"(\S+)\.\s+\d+\s+IN\s+A\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                host = m.group(1)
                ip = m.group(2)
                parsed["hosts"].append({"host": host, "ip": ip})
                if ip not in parsed["ips"]:
                    parsed["ips"].append(ip)

            # Nameservers
            if "NS" in line and "IN" in line:
                m = re.search(r"(\S+)\.\s+IN\s+NS\s+(\S+)", line)
                if m:
                    parsed["nameservers"].append(m.group(2))

        ev = Evidence.from_tool_output(
            tool_name="dnsenum",
            capability="dns_enumeration",
            evidence_type=EvidenceType.DNS,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"dnsenum {parsed['domain']}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("domain") and not parameters.get("target"):
            return False, ["Domain required"]
        return True, []


class DnsreconAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        domain = parameters.get("domain") or parameters.get("target")
        if not domain:
            raise ValueError("Domain required for dnsrecon")

        cmd = ["dnsrecon", "-d", domain]

        scan_type = parameters.get("scan_type", "std")  # std, rvl, brt, etc.
        cmd.extend(["-t", scan_type])

        if parameters.get("nameserver"):
            cmd.extend(["-n", parameters["nameserver"]])

        if parameters.get("wordlist"):
            cmd.extend(["-D", parameters["wordlist"]])

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed = {
            "domain": parameters.get("domain") or parameters.get("target"),
            "records": [],
        }

        # Parse dnsrecon output - often JSON or text
        # Look for A records, etc.
        for line in combined.splitlines():
            if " A " in line or " AAAA " in line or " CNAME " in line:
                parsed["records"].append(line.strip())

        ev = Evidence.from_tool_output(
            tool_name="dnsrecon",
            capability="dns_enumeration",
            evidence_type=EvidenceType.DNS,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"dnsrecon -d {parsed['domain']}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("domain") and not parameters.get("target"):
            return False, ["Domain required"]
        return True, []


DNSENUM_METADATA = ToolCapabilityMetadata(
    name="dnsenum",
    display_name="dnsenum - DNS Enumeration",
    category=CapabilityCategory.NETWORK_DISCOVERY,
    description="DNS enumeration utility where DNS assessment is within scope",
    tool_binary="dnsenum",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["domain", "optional_dnsserver", "optional_wordlist"],
    outputs=["dns_observation"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=30,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found", "invalid_parameters"],
    tags=["dns", "enumeration"],
    references=["https://github.com/fwaeytens/dnsenum"],
)

DNSRECON_METADATA = ToolCapabilityMetadata(
    name="dnsrecon",
    display_name="dnsrecon - DNS Reconnaissance",
    category=CapabilityCategory.NETWORK_DISCOVERY,
    description="DNS reconnaissance and enumeration",
    tool_binary="dnsrecon",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["domain", "optional_scan_type", "optional_nameserver"],
    outputs=["dns_observation"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=30,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found"],
    tags=["dns", "recon"],
    references=["https://github.com/darkoperator/dnsrecon"],
)


def register(registry):
    registry.register(DNSENUM_METADATA, DnsenumAdapter)
    registry.register(DNSRECON_METADATA, DnsreconAdapter)
