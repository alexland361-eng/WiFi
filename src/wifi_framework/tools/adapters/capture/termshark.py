"""
Adapters for termshark, Wireshark, mitmproxy, airbase-ng, etc.

Deep research:
  termshark: https://github.com/gcla/termshark, terminal UI for tshark
    termshark -i wlan0mon, termshark -r capture.pcap
  mitmproxy: https://mitmproxy.org/, HTTP/HTTPS interception
    mitmproxy, mitmdump -w flow, mitmdump -r flow -T json
  airbase-ng: https://www.aircrack-ng.org/doku.php?id=airbase-ng
    airbase-ng -e FakeAP -c 6 wlan0mon

These are not all inherently Wi-Fi radio tools but become relevant in later phases.
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


class TermsharkAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        cmd = ["termshark"]

        if interface:
            cmd.extend(["-i", interface])

        if parameters.get("read_file"):
            cmd.extend(["-r", parameters["read_file"]])

        # Termshark is interactive, for availability check use --help or version
        if not interface and not parameters.get("read_file"):
            cmd.append("--help")

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        ev = Evidence.from_tool_output(
            tool_name="termshark",
            capability="packet_capture",
            evidence_type=EvidenceType.CAPTURE,
            raw_output=combined,
            parsed_data={"interface": interface, "output": combined[:2000]},
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.LOW,
            execution_id=self.execution_id,
            raw_command=f"termshark -i {interface}" if interface else "termshark",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


class MitmproxyAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        # mitmproxy has mitmproxy (interactive), mitmdump (non-interactive), mitmweb
        mode = parameters.get("mode", "mitmdump")  # mitmdump, mitmproxy, mitmweb

        cmd = [mode]

        if parameters.get("write_file"):
            cmd.extend(["-w", parameters["write_file"]])

        if parameters.get("read_file"):
            cmd.extend(["-r", parameters["read_file"]])

        if parameters.get("listen_port"):
            cmd.extend(["--listen-port", str(parameters["listen_port"])])

        if not parameters.get("write_file") and not parameters.get("read_file") and not parameters.get("listen_port"):
            cmd.append("--help")

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        ev = Evidence.from_tool_output(
            tool_name="mitmproxy",
            capability="protocol_analysis",
            evidence_type=EvidenceType.GENERIC,
            raw_output=combined,
            parsed_data={
                "mode": parameters.get("mode", "mitmdump"),
                "write_file": parameters.get("write_file"),
                "read_file": parameters.get("read_file"),
            },
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.LOW,
            execution_id=self.execution_id,
            raw_command="mitmdump",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


class AirbaseNgAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        if not interface:
            raise ValueError("Interface required for airbase-ng")

        essid = parameters.get("essid") or parameters.get("ssid")
        if not essid:
            raise ValueError("ESSID required for airbase-ng")

        cmd = ["airbase-ng", "-e", essid]

        if parameters.get("channel"):
            cmd.extend(["-c", str(parameters["channel"])])

        if parameters.get("bssid"):
            cmd.extend(["-a", parameters["bssid"]])

        cmd.append(interface)
        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed = {
            "interface": interface,
            "essid": parameters.get("essid") or parameters.get("ssid"),
            "channel": parameters.get("channel"),
            "bssid": parameters.get("bssid"),
        }

        # Check if AP created
        if "Created AP" in combined or "Client" in combined:
            parsed["ap_created"] = True

        ev = Evidence.from_tool_output(
            tool_name="airbase-ng",
            capability="wireless_simulation",
            evidence_type=EvidenceType.ACCESS_POINT,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"airbase-ng -e {parsed['essid']} {interface}" if interface else "airbase-ng",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        if not parameters.get("essid") and not parameters.get("ssid"):
            return False, ["ESSID required"]
        return True, []


TERMSHARK_METADATA = ToolCapabilityMetadata(
    name="termshark",
    display_name="termshark - Terminal Wireshark",
    category=CapabilityCategory.PACKET_CAPTURE,
    description="Terminal-based interface around packet capture/analysis workflows",
    tool_binary="termshark",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["optional_interface", "optional_read_file"],
    outputs=["capture"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.PASSIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=10,
        produces_pcap=False,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found"],
    tags=["capture", "terminal", "wireshark"],
)

MITMPROXY_METADATA = ToolCapabilityMetadata(
    name="mitmproxy",
    display_name="mitmproxy - HTTP Interception",
    category=CapabilityCategory.PROTOCOL_ANALYSIS,
    description="HTTP/HTTPS interception and analysis framework - relevant after authorized assessment reaches network/application layer",
    tool_binary="mitmdump",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["optional_mode", "optional_write_file", "optional_read_file", "optional_listen_port"],
    outputs=["capture", "generic"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=False,
        estimated_duration_seconds=30,
        invasive=True,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found"],
    tags=["http", "mitm", "proxy"],
    references=["https://mitmproxy.org/"],
)

AIRBASE_METADATA = ToolCapabilityMetadata(
    name="airbase-ng",
    display_name="airbase-ng - AP Simulation",
    category=CapabilityCategory.WIRELESS_OBSERVATION,
    description="Wireless access-point simulation/testing for authorized assessment",
    tool_binary="airbase-ng",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=True,
        interface_capabilities=["monitor_mode"],
        privileges=["root"],
    ),
    inputs=["interface", "essid", "optional_channel", "optional_bssid"],
    outputs=["access_points"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_TESTING,
        persistent=True,
        estimated_duration_seconds=30,
        invasive=True,
        requires_authorization=True,
    ),
    failure_conditions=["interface_unavailable", "unsupported_driver", "insufficient_privileges"],
    tags=["ap", "simulation", "aircrack"],
    references=["https://www.aircrack-ng.org/doku.php?id=airbase-ng"],
)


def register(registry):
    registry.register(TERMSHARK_METADATA, TermsharkAdapter)
    registry.register(MITMPROXY_METADATA, MitmproxyAdapter)
    registry.register(AIRBASE_METADATA, AirbaseNgAdapter)
