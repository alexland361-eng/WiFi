"""
Remaining enumeration adapters: ldapsearch, rpcclient, ftp, wget

Deep research:
  ldapsearch: https://www.kali.org/tools/ldap-utils/, ldapsearch -x -h 192.168.1.1 -b "dc=example,dc=com"
  rpcclient: https://www.kali.org/tools/smbclient/, rpcclient -U "" 192.168.1.1 -c enumdomusers
  ftp: ftp 192.168.1.1, ftp client
  wget: wget -qO- http://192.168.1.1, wget -r http://192.168.1.1
  curl already implemented, wget as alternative
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


class LdapsearchAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        target = parameters.get("target") or parameters.get("host")
        if not target:
            raise ValueError("Target required for ldapsearch")

        cmd = ["ldapsearch", "-x", "-h", target]

        if parameters.get("base"):
            cmd.extend(["-b", parameters["base"]])

        if parameters.get("filter"):
            cmd.append(parameters["filter"])
        else:
            cmd.append("(objectClass=*)")

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed : Dict[str, Any] = {
            "host": parameters.get("target") or parameters.get("host"),
            "base": parameters.get("base"),
            "entries": [],
        }

        # Parse DN entries
        for line in combined.splitlines():
            if line.startswith("dn:"):
                parsed["entries"].append(line.strip())

        ev = Evidence.from_tool_output(
            tool_name="ldapsearch",
            capability="service_enumeration",
            evidence_type=EvidenceType.NETWORK_SERVICE,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"ldapsearch -x -h {parsed['host']}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("target") and not parameters.get("host"):
            return False, ["Target required"]
        return True, []


class RpcclientAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        target = parameters.get("target") or parameters.get("host")
        if not target:
            raise ValueError("Target required for rpcclient")

        cmd = ["rpcclient", "-U", parameters.get("user", "")]

        if parameters.get("password"):
            cmd[-1] = f"{parameters.get('user','')}%{parameters['password']}"
        else:
            cmd[-1] = f"{parameters.get('user','')}%"

        cmd.append(target)

        if parameters.get("command"):
            cmd.extend(["-c", parameters["command"]])
        else:
            cmd.extend(["-c", "enumdomusers"])

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed : Dict[str, Any] = {
            "host": parameters.get("target") or parameters.get("host"),
            "command": parameters.get("command", "enumdomusers"),
            "results": [],
        }

        for line in combined.splitlines():
            if "user:" in line.lower() or "rid:" in line.lower() or "group:" in line.lower():
                parsed["results"].append(line.strip())

        ev = Evidence.from_tool_output(
            tool_name="rpcclient",
            capability="service_enumeration",
            evidence_type=EvidenceType.NETWORK_SERVICE,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"rpcclient -U {parameters.get('user','')} {parsed['host']}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("target") and not parameters.get("host"):
            return False, ["Target required"]
        return True, []


class FtpAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        target = parameters.get("target") or parameters.get("host")
        if not target:
            raise ValueError("Target required for ftp")

        # Use curl for ftp to avoid interactive ftp client
        # curl ftp://192.168.1.1/ -l
        cmd = ["curl", "-s", f"ftp://{target}/"]

        if parameters.get("user") and parameters.get("password"):
            cmd.extend(["--user", f"{parameters['user']}:{parameters['password']}"])
        elif parameters.get("user"):
            cmd.extend(["--user", parameters["user"]])

        if parameters.get("path"):
            cmd = ["curl", "-s", f"ftp://{target}/{parameters['path']}"]

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed : Dict[str, Any] = {
            "host": parameters.get("target") or parameters.get("host"),
            "path": parameters.get("path", "/"),
            "listing": [],
        }

        for line in combined.splitlines():
            if line.strip():
                parsed["listing"].append(line.strip()[:200])

        ev = Evidence.from_tool_output(
            tool_name="ftp",
            capability="service_enumeration",
            evidence_type=EvidenceType.NETWORK_SERVICE,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"curl ftp://{parsed['host']}/",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("target") and not parameters.get("host"):
            return False, ["Target required"]
        return True, []


class WgetAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        url = parameters.get("url") or parameters.get("target")
        if not url:
            raise ValueError("URL required for wget")

        cmd = ["wget", "-qO-", url]

        if parameters.get("recursive"):
            cmd = ["wget", "-q", "-r", url]

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        # For -qO-, raw_output is the content, error_output may have logs
        content = raw_output if raw_output else ""

        parsed : Dict[str, Any] = {
            "url": parameters.get("url") or parameters.get("target"),
            "content_length": len(content),
            "content_snippet": content[:2000],
            "status": "success" if exit_code == 0 else "failed",
        }

        ev = Evidence.from_tool_output(
            tool_name="wget",
            capability="service_enumeration",
            evidence_type=EvidenceType.NETWORK_SERVICE,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"wget -qO- {parsed['url']}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("url") and not parameters.get("target"):
            return False, ["URL required"]
        return True, []


LDAPSEARCH_METADATA = ToolCapabilityMetadata(
    name="ldapsearch",
    display_name="ldapsearch - LDAP Enumeration",
    category=CapabilityCategory.SERVICE_ENUMERATION,
    description="LDAP enumeration for authorized assessment",
    tool_binary="ldapsearch",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["target", "optional_base", "optional_filter"],
    outputs=["network_services"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=15,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found"],
    tags=["ldap", "enumeration"],
)

RPCCLIENT_METADATA = ToolCapabilityMetadata(
    name="rpcclient",
    display_name="rpcclient - RPC Enumeration",
    category=CapabilityCategory.SERVICE_ENUMERATION,
    description="RPC client for SMB enumeration",
    tool_binary="rpcclient",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["target", "optional_user", "optional_password", "optional_command"],
    outputs=["network_services"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=15,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found"],
    tags=["rpc", "smb", "enumeration"],
)

FTP_METADATA = ToolCapabilityMetadata(
    name="ftp",
    display_name="ftp - FTP Enumeration",
    category=CapabilityCategory.SERVICE_ENUMERATION,
    description="FTP service enumeration via curl",
    tool_binary="curl",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["target", "optional_user", "optional_password", "optional_path"],
    outputs=["network_services"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=10,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found"],
    tags=["ftp", "enumeration"],
)

WGET_METADATA = ToolCapabilityMetadata(
    name="wget",
    display_name="wget - HTTP Retrieval",
    category=CapabilityCategory.SERVICE_ENUMERATION,
    description="HTTP retrieval for service enumeration",
    tool_binary="wget",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["url", "optional_recursive"],
    outputs=["network_services"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=10,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found"],
    tags=["http", "wget"],
)


def register(registry):
    registry.register(LDAPSEARCH_METADATA, LdapsearchAdapter)
    registry.register(RPCCLIENT_METADATA, RpcclientAdapter)
    registry.register(FTP_METADATA, FtpAdapter)
    registry.register(WGET_METADATA, WgetAdapter)
