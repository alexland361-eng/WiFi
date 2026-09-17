"""
Advanced enumeration adapters: smbmap, enum4linux-ng, nbtscan, snmpwalk, etc.

Deep research:
  smbmap: https://github.com/ShawnDEvans/smbmap, smbmap -H 192.168.1.1
  enum4linux-ng: https://github.com/cddmp/enum4linux-ng, enum4linux-ng 192.168.1.1
  nbtscan: nbtscan 192.168.1.0/24
  snmpwalk: snmpwalk -v2c -c public 192.168.1.1
  ldapsearch: ldapsearch -x -h 192.168.1.1 -b "dc=example,dc=com"
  rpcclient: rpcclient -U "" 192.168.1.1 -c enumdomusers
  ftp, wget, etc.

Each becomes relevant when wireless assessment transitions into authorized assessment of services.
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


class SmbmapAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        target = parameters.get("target") or parameters.get("host")
        if not target:
            raise ValueError("Target required for smbmap")

        cmd = ["smbmap", "-H", target]

        if parameters.get("user"):
            cmd.extend(["-u", parameters["user"]])
        if parameters.get("password"):
            cmd.extend(["-p", parameters["password"]])
        else:
            cmd.append("-R")  # Recursive listing attempt with null session

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed : Dict[str, Any] = {
            "host": parameters.get("target") or parameters.get("host"),
            "shares": [],
        }

        # Parse shares: "Disk Permissions" lines
        for line in combined.splitlines():
            if "READ" in line or "WRITE" in line or "Disk" in line:
                parsed["shares"].append(line.strip())

        ev = Evidence.from_tool_output(
            tool_name="smbmap",
            capability="service_enumeration",
            evidence_type=EvidenceType.NETWORK_SERVICE,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"smbmap -H {parsed['host']}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("target") and not parameters.get("host"):
            return False, ["Target required"]
        return True, []


class Enum4linuxNgAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        target = parameters.get("target") or parameters.get("host")
        if not target:
            raise ValueError("Target required for enum4linux-ng")

        cmd = ["enum4linux-ng"]

        # Options
        if parameters.get("all"):
            cmd.append("-A")
        else:
            cmd.append("-a")

        cmd.append(target)
        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed : Dict[str, Any] = {
            "host": parameters.get("target") or parameters.get("host"),
            "users": [],
            "shares": [],
            "groups": [],
        }

        # Very basic parsing
        for line in combined.splitlines():
            if "user:" in line.lower() or "username" in line.lower():
                parsed["users"].append(line.strip())
            if "share" in line.lower():
                parsed["shares"].append(line.strip())

        ev = Evidence.from_tool_output(
            tool_name="enum4linux-ng",
            capability="service_enumeration",
            evidence_type=EvidenceType.NETWORK_SERVICE,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"enum4linux-ng {parsed['host']}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("target") and not parameters.get("host"):
            return False, ["Target required"]
        return True, []


class NbtscanAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        target = parameters.get("target") or parameters.get("network") or parameters.get("host")
        if not target:
            raise ValueError("Target required for nbtscan")

        cmd = ["nbtscan"]

        if parameters.get("verbose"):
            cmd.append("-v")

        cmd.append(target)
        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed : Dict[str, Any] = {
            "target": parameters.get("target") or parameters.get("network"),
            "hosts": [],
        }

        # Parse nbtscan output: IP NetBIOS Name Server User MAC
        for line in combined.splitlines():
            m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+.*", line)
            if m:
                ip = m.group(1)
                name = m.group(2)
                parsed["hosts"].append({"ip": ip, "netbios_name": name, "raw": line.strip()})

        evidences = []
        for host in parsed["hosts"]:
            ev = Evidence.from_tool_output(
                tool_name="nbtscan",
                capability="service_enumeration",
                evidence_type=EvidenceType.NETWORK_HOST,
                raw_output=combined,
                parsed_data=host,
                parameters=parameters,
                interface=interface,
                confidence=ConfidenceLevel.MEDIUM,
                execution_id=self.execution_id,
                raw_command=f"nbtscan {parsed['target']}",
            )
            evidences.append(ev)

        if not evidences:
            # Generic evidence even if no hosts parsed
            ev = Evidence.from_tool_output(
                tool_name="nbtscan",
                capability="service_enumeration",
                evidence_type=EvidenceType.GENERIC,
                raw_output=combined,
                parsed_data=parsed,
                parameters=parameters,
                interface=interface,
                confidence=ConfidenceLevel.LOW,
                execution_id=self.execution_id,
                raw_command=f"nbtscan {parsed['target']}",
            )
            evidences.append(ev)

        return evidences

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("target") and not parameters.get("network") and not parameters.get("host"):
            return False, ["Target required"]
        return True, []


class SnmpwalkAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        target = parameters.get("target") or parameters.get("host")
        if not target:
            raise ValueError("Target required for snmpwalk")

        cmd = ["snmpwalk"]

        version = parameters.get("version", "2c")
        cmd.extend(["-v", version])

        community = parameters.get("community", "public")
        cmd.extend(["-c", community])

        cmd.append(target)

        if parameters.get("oid"):
            cmd.append(parameters["oid"])

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed : Dict[str, Any] = {
            "host": parameters.get("target") or parameters.get("host"),
            "oid": parameters.get("oid", ""),
            "results": [],
        }

        for line in combined.splitlines():
            if "SNMP" not in line and "=" in line:
                parsed["results"].append(line.strip()[:500])

        ev = Evidence.from_tool_output(
            tool_name="snmpwalk",
            capability="service_enumeration",
            evidence_type=EvidenceType.NETWORK_SERVICE,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"snmpwalk -v {parameters.get('version','2c')} -c {parameters.get('community','public')} {parsed['host']}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("target") and not parameters.get("host"):
            return False, ["Target required"]
        return True, []


# Metadata
SMBMAP_METADATA = ToolCapabilityMetadata(
    name="smbmap",
    display_name="smbmap - SMB Share Enumeration",
    category=CapabilityCategory.SERVICE_ENUMERATION,
    description="SMB share enumeration for authorized assessment",
    tool_binary="smbmap",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["target", "optional_user", "optional_password"],
    outputs=["network_services"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=15,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found"],
    tags=["smb", "enumeration"],
)

ENUM4LINUX_METADATA = ToolCapabilityMetadata(
    name="enum4linux-ng",
    display_name="enum4linux-ng - SMB Enumeration",
    category=CapabilityCategory.SERVICE_ENUMERATION,
    description="Comprehensive SMB enumeration",
    tool_binary="enum4linux-ng",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["target", "optional_all"],
    outputs=["network_services"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=30,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found"],
    tags=["smb", "enumeration"],
)

NBTSCAN_METADATA = ToolCapabilityMetadata(
    name="nbtscan",
    display_name="nbtscan - NetBIOS Scan",
    category=CapabilityCategory.NETWORK_DISCOVERY,
    description="NetBIOS name scanning",
    tool_binary="nbtscan",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["target", "optional_verbose"],
    outputs=["network_hosts"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=10,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found"],
    tags=["netbios", "discovery"],
)

SNMPWALK_METADATA = ToolCapabilityMetadata(
    name="snmpwalk",
    display_name="snmpwalk - SNMP Enumeration",
    category=CapabilityCategory.SERVICE_ENUMERATION,
    description="SNMP enumeration for authorized assessment",
    tool_binary="snmpwalk",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["target", "optional_version", "optional_community", "optional_oid"],
    outputs=["network_services"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=15,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found"],
    tags=["snmp", "enumeration"],
)


def register(registry):
    registry.register(SMBMAP_METADATA, SmbmapAdapter)
    registry.register(ENUM4LINUX_METADATA, Enum4linuxNgAdapter)
    registry.register(NBTSCAN_METADATA, NbtscanAdapter)
    registry.register(SNMPWALK_METADATA, SnmpwalkAdapter)
