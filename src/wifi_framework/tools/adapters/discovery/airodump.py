"""
Adapter for `airodump-ng` - wireless discovery and packet observation.
"""
from __future__ import annotations

import os
import tempfile
import time
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
from ....core.models.evidence import Evidence
from ....parsers.airodump import airodump_to_evidences, parse_airodump_csv


class AirodumpNgAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        if not interface:
            raise ValueError("Interface required for airodump-ng")

        # Build command with output to temp file for CSV parsing
        cmd = ["airodump-ng"]

        # Channel
        channel = parameters.get("channel")
        if channel:
            cmd.extend(["-c", str(channel)])

        # BSSID filter
        bssid = parameters.get("bssid") or parameters.get("target_bssid")
        if bssid:
            cmd.extend(["--bssid", bssid])

        # Output prefix - we use temp file
        output_prefix = parameters.get("output_prefix")
        if not output_prefix:
            # Create temp file prefix
            tmpdir = tempfile.gettempdir()
            output_prefix = os.path.join(tmpdir, f"airodump_{int(time.time())}")

        cmd.extend(["-w", output_prefix])

        # Output format - CSV is most useful for parsing
        output_format = parameters.get("output_format", "csv")
        if output_format:
            cmd.extend(["--output-format", output_format])

        # Write interval
        cmd.extend(["--write-interval", "1"])

        # Duration - we will run with timeout, not infinite
        # airodump-ng runs indefinitely, so we need to handle timeout via executor
        # Add interface last
        cmd.append(interface)

        # Store output prefix for parsing
        self._last_output_prefix = output_prefix

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        # Try to find CSV file
        output_prefix = getattr(self, "_last_output_prefix", None) or parameters.get("output_prefix")
        csv_content = None

        if output_prefix:
            # airodump-ng names its CSV by the rotation index it reached, so every
            # candidate is tried rather than assuming ``-01``.
            possible_paths = [
                f"{output_prefix}-01.csv",
                f"{output_prefix}.csv",
                f"{output_prefix}-01.kismet.csv",
                f"{output_prefix}.kismet.csv",
            ]
            for path in possible_paths:
                if os.path.exists(path):
                    try:
                        with open(path, "r", errors="ignore") as f:
                            csv_content = f.read()
                        # Cleanup
                        try:
                            os.remove(path)
                            # Also remove other files with same prefix
                            base_dir = os.path.dirname(path)
                            base_name = os.path.basename(output_prefix)
                            for fname in os.listdir(base_dir):
                                if fname.startswith(base_name):
                                    try:
                                        os.remove(os.path.join(base_dir, fname))
                                    except OSError:
                                        pass
                        except OSError:
                            pass
                        break
                    except OSError:
                        continue

        # Parse evidences. Problems are collected rather than left inside the parser:
        # a screen-output fallback that found nothing and a radio that genuinely saw
        # nothing both produce an empty evidence list, and the difference has to reach
        # the Evidence Engine or the assessment records "no access points observed".
        parse_issues: List[str] = []
        evidences = airodump_to_evidences(
            raw_output=raw_output + "\n" + error_output,
            csv_content=csv_content,
            interface=interface,
            execution_id=self.execution_id,
            issues=parse_issues,
        )
        self.parse_warnings.extend(parse_issues)

        return evidences

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        errors = []
        # Channel validation
        if "channel" in parameters and parameters["channel"] is not None:
            try:
                ch = int(parameters["channel"])
                if not 1 <= ch <= 196:
                    errors.append(f"Invalid channel {ch}")
            except (ValueError, TypeError):
                errors.append(f"Channel must be integer, got {parameters['channel']}")

        # BSSID validation
        if "bssid" in parameters and parameters["bssid"]:
            from ....utils.validation import validate_mac

            valid, msg = validate_mac(parameters["bssid"])
            if not valid:
                errors.append(f"BSSID: {msg}")

        if errors:
            return False, errors
        return True, []

    def custom_requirement_check(self, interface: str | None, parameters: Dict[str, Any]):
        # airodump-ng requires monitor mode, but we check at execution time
        # For now, just ensure interface provided
        if not interface:
            return False, "Interface required for airodump-ng"
        return True, ""


METADATA = ToolCapabilityMetadata(
    name="airodump-ng",
    display_name="airodump-ng - Wireless Discovery",
    category=CapabilityCategory.WIRELESS_OBSERVATION,
    description="Wireless network and client observation, including AP/client relationships and radio-level information",
    tool_binary="airodump-ng",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=True,
        interface_capabilities=["monitor_mode"],
        privileges=["root"],
    ),
    inputs=["interface", "optional_channel", "optional_bssid", "optional_output_prefix", "optional_output_format"],
    outputs=["access_points", "clients", "channels", "signal_observations", "authentication_observations"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_OBSERVATION,
        persistent=True,
        estimated_duration_seconds=30,
        produces_pcap=True,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=[
        "interface_unavailable",
        "unsupported_driver",
        "insufficient_privileges",
        "invalid_parameters",
        "timeout",
    ],
    tags=["wireless", "discovery", "aircrack"],
)


ADAPTER_CLASS = AirodumpNgAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
