"""
Advanced Aircrack-ng suite adapters: airserv-ng, airdriver-ng, packetforge-ng, ivstools, wpaclean, airdecloak-ng

Deep research:
  airserv-ng: https://www.aircrack-ng.org/doku.php?id=airserv-ng - remote wireless interface access
    airserv-ng -d -c 1 -p 666 -v
  airdriver-ng: https://www.aircrack-ng.org/doku.php?id=airdriver-ng - driver-related
    airdriver-ng
  packetforge-ng: https://www.aircrack-ng.org/doku.php?id=packetforge-ng - packet construction
    packetforge-ng -0 -a 00:11:22:33:44:55 -h 11:22:33:44:55:66 -k 192.168.1.1 -l 192.168.1.100 -y fragment.xor -w custom.cap
  ivstools: https://www.aircrack-ng.org/doku.php?id=ivstools - IV manipulation
    ivstools --merge
  wpaclean: https://www.aircrack-ng.org/doku.php?id=wpaclean - WPA capture cleanup
    wpaclean cleaned.cap capture.cap
  airdecloak-ng: https://www.aircrack-ng.org/doku.php?id=airdecloak-ng - cloaked frames analysis
    airdecloak-ng -i capture.pcap --ssid MyNetwork
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


class AirservNgAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        cmd = ["airserv-ng"]

        if parameters.get("device"):
            cmd.extend(["-d", parameters["device"]])
        if parameters.get("channel"):
            cmd.extend(["-c", str(parameters["channel"])])
        if parameters.get("port"):
            cmd.extend(["-p", str(parameters["port"])])
        if parameters.get("verbose"):
            cmd.append("-v")

        if not parameters.get("device") and not parameters.get("channel") and not parameters.get("port"):
            cmd.append("--help")

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output
        ev = Evidence.from_tool_output(
            tool_name="airserv-ng",
            capability="wireless_interface_management",
            evidence_type=EvidenceType.GENERIC,
            raw_output=combined,
            parsed_data={"device": parameters.get("device"), "channel": parameters.get("channel")},
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.LOW,
            execution_id=self.execution_id,
            raw_command="airserv-ng",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


class PacketforgeNgAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        cmd = ["packetforge-ng"]

        # Mode
        mode = parameters.get("mode", "0")  # 0 ARP, etc.
        cmd.extend(["-" + str(mode)])

        if parameters.get("bssid"):
            cmd.extend(["-a", parameters["bssid"]])
        if parameters.get("client"):
            cmd.extend(["-h", parameters["client"]])
        if parameters.get("src_ip"):
            cmd.extend(["-k", parameters["src_ip"]])
        if parameters.get("dst_ip"):
            cmd.extend(["-l", parameters["dst_ip"]])
        if parameters.get("fragment_file"):
            cmd.extend(["-y", parameters["fragment_file"]])
        if parameters.get("output_file"):
            cmd.extend(["-w", parameters["output_file"]])
        else:
            cmd.extend(["-w", "/tmp/packetforge.cap"])

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output
        ev = Evidence.from_tool_output(
            tool_name="packetforge-ng",
            capability="packet_construction",
            evidence_type=EvidenceType.CAPTURE,
            raw_output=combined,
            parsed_data={
                "bssid": parameters.get("bssid"),
                "output_file": parameters.get("output_file", "/tmp/packetforge.cap"),
                "success": exit_code == 0,
            },
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM if exit_code == 0 else ConfidenceLevel.LOW,
            execution_id=self.execution_id,
            raw_command="packetforge-ng",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


class WpacleanAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        output = parameters.get("output_file") or "/tmp/cleaned.cap"
        input_file = parameters.get("input_file") or parameters.get("capture_file")
        if not input_file:
            raise ValueError("input_file required for wpaclean")

        return ["wpaclean", output, input_file]

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output
        ev = Evidence.from_tool_output(
            tool_name="wpaclean",
            capability="capture_cleanup",
            evidence_type=EvidenceType.CAPTURE,
            raw_output=combined,
            parsed_data={
                "input_file": parameters.get("input_file"),
                "output_file": parameters.get("output_file", "/tmp/cleaned.cap"),
                "success": exit_code == 0,
            },
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"wpaclean {parameters.get('output_file','/tmp/cleaned.cap')} {parameters.get('input_file')}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("input_file") and not parameters.get("capture_file"):
            return False, ["input_file required"]
        return True, []


class AirdecloakNgAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        cmd = ["airdecloak-ng"]

        if parameters.get("input_file"):
            cmd.extend(["-i", parameters["input_file"]])
        else:
            raise ValueError("input_file required for airdecloak-ng")

        if parameters.get("ssid"):
            cmd.extend(["--ssid", parameters["ssid"]])

        if parameters.get("output_file"):
            cmd.extend(["--output", parameters["output_file"]])

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed = {
            "input_file": parameters.get("input_file"),
            "ssid": parameters.get("ssid"),
            "success": exit_code == 0,
        }

        # Parse decloaked SSIDs
        import re

        for line in combined.splitlines():
            m = re.search(r"SSID.*?:\s*(.+)", line, re.IGNORECASE)
            if m:
                parsed["decloaked_ssid"] = m.group(1).strip()

        ev = Evidence.from_tool_output(
            tool_name="airdecloak-ng",
            capability="capture_analysis",
            evidence_type=EvidenceType.ACCESS_POINT,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"airdecloak-ng -i {parsed['input_file']}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("input_file"):
            return False, ["input_file required"]
        return True, []


# Metadata
AIRSERV_METADATA = ToolCapabilityMetadata(
    name="airserv-ng",
    display_name="airserv-ng - Remote Interface Access",
    category=CapabilityCategory.WIRELESS_INTERFACE,
    description="Remote wireless-interface access for distributed assessment",
    tool_binary="airserv-ng",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=["root"],
    ),
    inputs=["optional_device", "optional_channel", "optional_port"],
    outputs=["generic"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.CONFIGURATION,
        persistent=True,
        estimated_duration_seconds=10,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found"],
    tags=["remote", "aircrack"],
    references=["https://www.aircrack-ng.org/doku.php?id=airserv-ng"],
)

PACKETFORGE_METADATA = ToolCapabilityMetadata(
    name="packetforge-ng",
    display_name="packetforge-ng - Packet Construction",
    category=CapabilityCategory.PROTOCOL_ANALYSIS,
    description="Packet construction for authorized wireless testing",
    tool_binary="packetforge-ng",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["optional_bssid", "optional_client", "optional_src_ip", "optional_dst_ip", "optional_fragment_file", "optional_output_file"],
    outputs=["capture"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_TESTING,
        persistent=False,
        estimated_duration_seconds=5,
        invasive=True,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found", "invalid_parameters"],
    tags=["packet", "crafting", "aircrack"],
    references=["https://www.aircrack-ng.org/doku.php?id=packetforge-ng"],
)

WPACLEAN_METADATA = ToolCapabilityMetadata(
    name="wpaclean",
    display_name="wpaclean - WPA Capture Cleanup",
    category=CapabilityCategory.WPA_ASSESSMENT,
    description="WPA capture cleanup utility",
    tool_binary="wpaclean",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["input_file", "optional_output_file"],
    outputs=["capture"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.OFFLINE_ANALYSIS,
        persistent=False,
        estimated_duration_seconds=10,
        invasive=False,
        requires_authorization=False,
    ),
    failure_conditions=["tool_not_found"],
    tags=["cleanup", "wpa", "aircrack"],
    references=["https://www.aircrack-ng.org/doku.php?id=wpaclean"],
)

AIRDECLOAK_METADATA = ToolCapabilityMetadata(
    name="airdecloak-ng",
    display_name="airdecloak-ng - Cloaked Frame Analysis",
    category=CapabilityCategory.WIRELESS_OBSERVATION,
    description="Analysis of captures containing cloaked frames to reveal hidden SSIDs",
    tool_binary="airdecloak-ng",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["input_file", "optional_ssid", "optional_output_file"],
    outputs=["access_points"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.OFFLINE_ANALYSIS,
        persistent=False,
        estimated_duration_seconds=10,
        invasive=False,
        requires_authorization=False,
    ),
    failure_conditions=["tool_not_found"],
    tags=["cloaked", "hidden", "aircrack"],
    references=["https://www.aircrack-ng.org/doku.php?id=airdecloak-ng"],
)


def register(registry):
    registry.register(AIRSERV_METADATA, AirservNgAdapter)
    registry.register(PACKETFORGE_METADATA, PacketforgeNgAdapter)
    registry.register(WPACLEAN_METADATA, WpacleanAdapter)
    registry.register(AIRDECLOAK_METADATA, AirdecloakNgAdapter)
