"""
Generic adapters for enumeration tools - smbclient, curl, openssl, etc.

These are not inherently Wi-Fi tools. They become relevant when wireless assessment
transitions into authorized assessment of services reachable through wireless network.
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


class CurlAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        url = parameters.get("url") or parameters.get("target")
        if not url:
            raise ValueError("URL required for curl")

        cmd = ["curl", "-s", "-i"]

        if parameters.get("insecure"):
            cmd.append("-k")

        if parameters.get("method"):
            cmd.extend(["-X", parameters["method"]])

        if parameters.get("headers"):
            for k, v in parameters["headers"].items():
                cmd.extend(["-H", f"{k}: {v}"])

        cmd.append(url)
        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed : Dict[str, Any] = {
            "url": parameters.get("url") or parameters.get("target"),
            "status_code": None,
            "headers": {},
            "body": "",
        }

        # Try to parse HTTP status
        m = re.search(r"HTTP/\d\.\d\s+(\d+)", combined)
        if m:
            try:
                parsed["status_code"] = int(m.group(1))
            except ValueError:
                pass

        # Split headers and body
        if "\r\n\r\n" in combined:
            header_part, body = combined.split("\r\n\r\n", 1)
            parsed["body"] = body[:2000]
        elif "\n\n" in combined:
            parts = combined.split("\n\n", 1)
            if len(parts) == 2:
                parsed["body"] = parts[1][:2000]

        ev = Evidence.from_tool_output(
            tool_name="curl",
            capability="service_enumeration",
            evidence_type=EvidenceType.NETWORK_SERVICE,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"curl {parsed['url']}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("url") and not parameters.get("target"):
            return False, ["URL required"]
        return True, []


class OpensslAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        target = parameters.get("target") or parameters.get("host")
        if not target:
            raise ValueError("Target required for openssl")

        port = parameters.get("port", "443")
        cmd = ["openssl", "s_client", "-connect", f"{target}:{port}"]

        if parameters.get("servername"):
            cmd.extend(["-servername", parameters["servername"]])

        # We need to provide input to close connection quickly
        # Use -brief or timeout via execution timeout

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed : Dict[str, Any] = {
            "host": parameters.get("target") or parameters.get("host"),
            "port": parameters.get("port", "443"),
        }

        # Parse certificate info
        if "Certificate chain" in combined:
            parsed["has_certificate"] = True

        # Parse protocol
        m = re.search(r"Protocol\s*:\s*(\S+)", combined)
        if m:
            parsed["protocol"] = m.group(1)

        # Cipher
        m = re.search(r"Cipher\s*:\s*(\S+)", combined)
        if m:
            parsed["cipher"] = m.group(1)

        ev = Evidence.from_tool_output(
            tool_name="openssl",
            capability="service_enumeration",
            evidence_type=EvidenceType.NETWORK_SERVICE,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"openssl s_client -connect {parsed['host']}:{parsed['port']}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("target") and not parameters.get("host"):
            return False, ["Target required"]
        return True, []


class SmbclientAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        target = parameters.get("target") or parameters.get("host")
        if not target:
            raise ValueError("Target required for smbclient")

        share = parameters.get("share", "")
        if share:
            target_path = f"//{target}/{share}"
        else:
            target_path = f"//{target}/"

        cmd = ["smbclient", target_path, "-N"]  # No password by default

        if parameters.get("command"):
            cmd.extend(["-c", parameters["command"]])
        else:
            cmd.extend(["-c", "ls"])

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed : Dict[str, Any] = {
            "host": parameters.get("target") or parameters.get("host"),
            "share": parameters.get("share", ""),
        }

        # Parse file listing if present
        files = []
        for line in combined.splitlines():
            # Simple heuristic for smbclient ls output
            if "." in line and len(line.split()) >= 2:
                files.append(line.strip())

        parsed["files"] = files[:20]
        parsed["accessible"] = exit_code == 0

        ev = Evidence.from_tool_output(
            tool_name="smbclient",
            capability="service_enumeration",
            evidence_type=EvidenceType.NETWORK_SERVICE,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"smbclient //{parsed['host']}/{parsed['share']}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("target") and not parameters.get("host"):
            return False, ["Target required"]
        return True, []


# Metadata
CURL_METADATA = ToolCapabilityMetadata(
    name="curl",
    display_name="curl - HTTP Enumeration",
    category=CapabilityCategory.SERVICE_ENUMERATION,
    description="HTTP client for service enumeration after wireless access",
    tool_binary="curl",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["url", "optional_method", "optional_headers"],
    outputs=["network_services"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=10,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found", "invalid_parameters"],
    tags=["http", "enumeration"],
)

OPENSSL_METADATA = ToolCapabilityMetadata(
    name="openssl_s_client",
    display_name="openssl s_client - TLS Enumeration",
    category=CapabilityCategory.SERVICE_ENUMERATION,
    description="TLS enumeration via openssl s_client",
    tool_binary="openssl",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["target", "optional_port", "optional_servername"],
    outputs=["network_services"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=10,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found"],
    tags=["tls", "enumeration"],
)

SMBCLIENT_METADATA = ToolCapabilityMetadata(
    name="smbclient",
    display_name="smbclient - SMB Enumeration",
    category=CapabilityCategory.SERVICE_ENUMERATION,
    description="SMB client for service enumeration",
    tool_binary="smbclient",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["target", "optional_share"],
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


def register(registry):
    registry.register(CURL_METADATA, CurlAdapter)
    registry.register(OPENSSL_METADATA, OpensslAdapter)
    registry.register(SMBCLIENT_METADATA, SmbclientAdapter)
