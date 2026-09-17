"""
Framework adapters: Metasploit, Impacket, Responder, OpenVAS/Greenbone

Deep research:
  Metasploit: https://www.metasploit.com/, https://www.kali.org/tools/metasploit-framework/
    msfconsole -x "use exploit/...; set RHOSTS 192.168.1.1; check; run"
    msfvenom, etc.
  Impacket: https://github.com/fortra/impacket, https://www.kali.org/tools/impacket/
    impacket-psexec, impacket-secretsdump, impacket-psexec user:pass@192.168.1.1
  Responder: https://github.com/lgandx/Responder, https://www.kali.org/tools/responder/
    responder -I wlan0 -w -r -f
  OpenVAS/Greenbone: https://www.greenbone.github.io/docs/latest/
    gvm-cli, openvas, gvm-start

Philosophy: Belong to broader network-security phase rather than initial wireless reconnaissance.
Can be used for authorized vulnerability validation and exploitation testing after applicable vulnerability identified.
Highly invasive, requires explicit authorization, scope enforcement critical.
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


class MetasploitAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        # Metasploit can be run via msfconsole with -x commands or via msf-cli
        # For safety and auditability, we support check mode and limited commands

        if parameters.get("module"):
            module = parameters["module"]
            cmd = ["msfconsole", "-q", "-x", f"use {module};"]

            if parameters.get("rhosts"):
                cmd[-1] += f" set RHOSTS {parameters['rhosts']};"

            if parameters.get("options"):
                for k, v in parameters["options"].items():
                    cmd[-1] += f" set {k} {v};"

            # Default to check, not run, for safety
            action = parameters.get("action", "check")
            if action == "check":
                cmd[-1] += " check; exit"
            elif action == "run" and parameters.get("allow_run"):
                cmd[-1] += " run; exit"
            else:
                cmd[-1] += " check; exit"

            return cmd
        else:
            # Version check
            return ["msfconsole", "--version"]

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed : Dict[str, Any] = {
            "module": parameters.get("module"),
            "rhosts": parameters.get("rhosts"),
            "action": parameters.get("action", "check"),
        }

        # Parse check results
        if "is vulnerable" in combined.lower() or "vulnerable" in combined.lower():
            parsed["vulnerable"] = True
        elif "not vulnerable" in combined.lower() or "safe" in combined.lower():
            parsed["vulnerable"] = False

        # Parse session opened
        if "session" in combined.lower() and "opened" in combined.lower():
            parsed["session_opened"] = True

        ev = Evidence.from_tool_output(
            tool_name="metasploit",
            capability="vulnerability_validation",
            evidence_type=EvidenceType.VULNERABILITY,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.HIGH if parsed.get("vulnerable") else ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"msfconsole -x use {parsed['module']}" if parsed.get("module") else "msfconsole --version",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        # For safety, require explicit allow_run for actual exploitation
        if parameters.get("action") == "run" and not parameters.get("allow_run"):
            return False, ["Exploitation (run) requires explicit allow_run=true for safety"]
        return True, []


class ImpacketAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        # Impacket is a collection of tools: impacket-psexec, impacket-secretsdump, etc.
        tool = parameters.get("impacket_tool", "psexec")  # psexec, secretsdump, etc.

        if tool == "psexec":
            target = parameters.get("target")
            if not target:
                raise ValueError("Target required for impacket-psexec")

            cmd = ["impacket-psexec"]

            if parameters.get("username") and parameters.get("password"):
                cmd.append(f"{parameters['username']}:{parameters['password']}@{target}")
            elif parameters.get("username"):
                cmd.append(f"{parameters['username']}@{target}")
            else:
                cmd.append(target)

            if parameters.get("command"):
                cmd.append(parameters["command"])

            return cmd
        elif tool == "secretsdump":
            target = parameters.get("target")
            if not target:
                raise ValueError("Target required for impacket-secretsdump")

            cmd = ["impacket-secretsdump"]

            if parameters.get("username") and parameters.get("password"):
                cmd.append(f"{parameters['username']}:{parameters['password']}@{target}")
            else:
                cmd.append(target)

            return cmd
        else:
            # Generic impacket tool
            cmd = [f"impacket-{tool}"]

            if parameters.get("target"):
                cmd.append(parameters["target"])

            if not parameters.get("target"):
                cmd.append("--help")

            return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed : Dict[str, Any] = {
            "impacket_tool": parameters.get("impacket_tool", "psexec"),
            "target": parameters.get("target"),
        }

        # Parse results
        if "Administrator" in combined or "root" in combined.lower():
            parsed["potential_access"] = True

        ev = Evidence.from_tool_output(
            tool_name="impacket",
            capability="credential_assessment",
            evidence_type=EvidenceType.CREDENTIAL,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"impacket-{parsed['impacket_tool']} {parsed['target']}" if parsed.get("target") else "impacket",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if parameters.get("impacket_tool") in ["psexec", "secretsdump"] and not parameters.get("target"):
            return False, ["Target required for this impacket tool"]
        return True, []


class ResponderAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        cmd = ["responder"]

        if interface:
            cmd.extend(["-I", interface])
        elif parameters.get("interface"):
            cmd.extend(["-I", parameters["interface"]])

        # Options: -w (Wpad), -r (Wpad), -f (Fingerprint), etc.
        if parameters.get("wpad"):
            cmd.append("-w")
        if parameters.get("wpad_proxy"):
            cmd.append("-r")
        if parameters.get("fingerprint"):
            cmd.append("-f")

        if not interface and not parameters.get("interface"):
            cmd.append("--help")

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed : Dict[str, Any] = {
            "interface": interface or parameters.get("interface"),
            "captured_hashes": [],
        }

        # Parse captured hashes
        # Responder outputs like [SMB] NTLMv2-SSP ... or [HTTP] ...

        for line in combined.splitlines():
            if "NTLM" in line or "Hash" in line or "[SMB]" in line or "[HTTP]" in line:
                parsed["captured_hashes"].append(line.strip()[:500])

        ev = Evidence.from_tool_output(
            tool_name="responder",
            capability="credential_capture",
            evidence_type=EvidenceType.CREDENTIAL,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.HIGH if parsed["captured_hashes"] else ConfidenceLevel.LOW,
            execution_id=self.execution_id,
            raw_command=f"responder -I {parsed['interface']}" if parsed.get("interface") else "responder",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


class OpenVASAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        # OpenVAS/Greenbone has gvm-cli, openvas, etc.
        # For simplicity, support version check and scan via gvm-cli

        if parameters.get("target"):
            # Example: gvm-cli --gmp-username admin --gmp-password admin socket --xml "<create_target>..."
            # For safety, we only do version check unless explicitly allowed
            if not parameters.get("allow_scan"):
                return ["gvm-cli", "--help"]

            cmd = ["gvm-cli", "socket", "--xml", "<get_targets/>"]
            return cmd
        else:
            return ["openvas", "--version"]

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed : Dict[str, Any] = {
            "target": parameters.get("target"),
            "version_info": combined[:1000],
        }

        ev = Evidence.from_tool_output(
            tool_name="openvas",
            capability="vulnerability_assessment",
            evidence_type=EvidenceType.VULNERABILITY,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.LOW,
            execution_id=self.execution_id,
            raw_command="openvas --version",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if parameters.get("target") and not parameters.get("allow_scan"):
            return False, ["OpenVAS scan requires allow_scan=true for safety and authorization"]
        return True, []


METASPLOIT_METADATA = ToolCapabilityMetadata(
    name="metasploit",
    display_name="Metasploit Framework - Vuln Validation",
    category=CapabilityCategory.FRAMEWORK,
    description="Authorized vulnerability validation and exploitation testing after applicable vulnerability identified - highly invasive",
    tool_binary="msfconsole",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["optional_module", "optional_rhosts", "optional_action", "optional_allow_run"],
    outputs=["vulnerability"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_TESTING,
        persistent=False,
        estimated_duration_seconds=60,
        invasive=True,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found", "invalid_parameters"],
    tags=["framework", "exploitation", "vuln"],
    references=["https://www.metasploit.com/", "https://www.kali.org/tools/metasploit-framework/"],
)

IMPACKET_METADATA = ToolCapabilityMetadata(
    name="impacket",
    display_name="Impacket - Protocol Implementation",
    category=CapabilityCategory.FRAMEWORK,
    description="Protocol implementations and utilities for authorized Windows/network assessment",
    tool_binary="impacket-psexec",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["optional_impacket_tool", "optional_target", "optional_username", "optional_password"],
    outputs=["credential_observation", "network_services"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_TESTING,
        persistent=False,
        estimated_duration_seconds=30,
        invasive=True,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found"],
    tags=["framework", "impacket", "windows"],
    references=["https://github.com/fortra/impacket"],
)

RESPONDER_METADATA = ToolCapabilityMetadata(
    name="responder",
    display_name="Responder - Auth Capture",
    category=CapabilityCategory.FRAMEWORK,
    description="Relevant to specific authorized network authentication/security assessments - captures NTLM hashes",
    tool_binary="responder",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        interface_capabilities=[],
        privileges=["root"],
    ),
    inputs=["optional_interface", "optional_wpad", "optional_fingerprint"],
    outputs=["credential_observation"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_TESTING,
        persistent=True,
        estimated_duration_seconds=60,
        invasive=True,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found", "insufficient_privileges"],
    tags=["responder", "ntlm", "credential"],
    references=["https://github.com/lgandx/Responder"],
)

OPENVAS_METADATA = ToolCapabilityMetadata(
    name="openvas",
    display_name="OpenVAS/Greenbone - Vuln Assessment",
    category=CapabilityCategory.VULNERABILITY_ASSESSMENT,
    description="Broader vulnerability assessment after network and hosts identified - only when prerequisites satisfied",
    tool_binary="openvas",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["optional_target", "optional_allow_scan"],
    outputs=["vulnerability"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=300,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found"],
    tags=["vuln", "openvas", "greenbone"],
    references=["https://www.greenbone.github.io/docs/latest/"],
)


def register(registry):
    registry.register(METASPLOIT_METADATA, MetasploitAdapter)
    registry.register(IMPACKET_METADATA, ImpacketAdapter)
    registry.register(RESPONDER_METADATA, ResponderAdapter)
    registry.register(OPENVAS_METADATA, OpenVASAdapter)
