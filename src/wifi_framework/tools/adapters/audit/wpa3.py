"""Passive WPA3 configuration/status audits through real control clients."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
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
from ....parsers.wpa_config import (
    detect_eap_pwd_user_file,
    parse_wpa_config,
    sanitize_wpa_config,
)
from ....parsers.wpa_status import parse_wpa_cli_status


class _Wpa3ControlAuditAdapter(ToolAdapterBase):
    """Shared parser for hostapd_cli and wpa_cli get_config output."""

    cli_binary = ""
    capability_name = ""

    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        if not interface:
            raise ValueError(f"Interface required for {self.cli_binary} WPA3 audit")
        return [self.cli_binary, "-i", interface, "get_config"]

    def parse_output(
        self,
        raw_output: str,
        error_output: str,
        exit_code: int,
        parameters: Dict[str, Any],
        interface: str | None,
    ) -> List[Evidence]:
        safe_output = sanitize_wpa_config(raw_output)
        combined = safe_output + ("\n" + sanitize_wpa_config(error_output) if error_output else "")
        if exit_code != 0 and not combined.strip():
            return []
        issues: List[str] = []
        posture = parse_wpa_config(
            combined,
            source=f"{self.cli_binary} get_config",
            issues=issues,
        )
        user_file = parameters.get("eap_user_file")
        if user_file is not None:
            try:
                user_text = Path(user_file).read_text(encoding="utf-8")
                posture.eap_pwd_configured = detect_eap_pwd_user_file(user_text, issues)
            except OSError as exc:
                issues.append(f"EAP user file could not be read: {exc}")
        self.parse_warnings.extend(issues)
        data = asdict(posture)
        # The dataclass contains only posture, not secrets; safe_output is what enters
        # Evidence.raw_output, so the original control-client response is not retained here.
        return [
            Evidence.from_tool_output(
                tool_name=self.cli_binary,
                capability=self.capability_name,
                evidence_type=EvidenceType.AUTHENTICATION,
                raw_output=combined,
                parsed_data=data,
                parameters=parameters,
                interface=interface,
                confidence=ConfidenceLevel.HIGH,
                execution_id=self.execution_id,
                raw_command=f"{self.cli_binary} -i {interface} get_config",
            )
        ]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        user_file = parameters.get("eap_user_file")
        if user_file is None:
            return True, []
        if not isinstance(user_file, str) or not user_file.strip():
            return False, ["eap_user_file must be a non-empty path"]
        path = Path(user_file).expanduser()
        if not path.is_file():
            return False, [f"EAP user file does not exist: {user_file}"]
        return True, []


class HostapdWpa3AuditAdapter(_Wpa3ControlAuditAdapter):
    cli_binary = "hostapd_cli"
    capability_name = "hostapd_wpa3_audit"


class WpaSupplicantWpa3AuditAdapter(_Wpa3ControlAuditAdapter):
    cli_binary = "wpa_cli"
    capability_name = "wpa_supplicant_wpa3_audit"


class WpaSupplicantStatusAuditAdapter(ToolAdapterBase):
    """Observe the SAE group selected by an existing wpa_supplicant connection."""

    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        if not interface:
            raise ValueError("Interface required for wpa_cli status audit")
        return ["wpa_cli", "-i", interface, "status"]

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int,
        parameters: Dict[str, Any], interface: str | None,
    ) -> List[Evidence]:
        combined = raw_output or error_output
        if exit_code != 0 and not combined.strip():
            return []
        issues: List[str] = []
        posture = parse_wpa_cli_status(combined, interface=interface, issues=issues)
        self.parse_warnings.extend(issues)
        data = asdict(posture)
        data["connection_state"] = next(
            (line.split("=", 1)[1].strip() for line in combined.splitlines()
             if line.startswith("wpa_state=")),
            None,
        )
        return [
            Evidence.from_tool_output(
                tool_name="wpa_cli",
                capability="wpa_supplicant_wpa3_status",
                evidence_type=EvidenceType.AUTHENTICATION,
                raw_output=combined,
                parsed_data=data,
                parameters=parameters,
                interface=interface,
                confidence=ConfidenceLevel.HIGH,
                execution_id=self.execution_id,
                raw_command=f"wpa_cli -i {interface} status",
            )
        ]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        return True, []


def _metadata(name: str, display_name: str, binary: str) -> ToolCapabilityMetadata:
    return ToolCapabilityMetadata(
        name=name,
        display_name=display_name,
        category=CapabilityCategory.WPA_ASSESSMENT,
        description="Read WPA3/SAE posture from the real control client without active SAE probing",
        tool_binary=binary,
        version="1.0",
        requirements=CapabilityRequirements(
            operating_systems=[OperatingSystem.LINUX],
            interface_required=True,
            privileges=[],
        ),
        inputs=["interface", "optional_eap_user_file"],
        outputs=["wpa3_posture", "sae_groups", "sae_pwe", "pmf_status", "eap_pwd_status"],
        operational_properties=OperationalProperties(
            mode=OperationalMode.CONFIGURATION,
            persistent=False,
            estimated_duration_seconds=3,
            invasive=False,
            requires_authorization=False,
        ),
        failure_conditions=["control_socket_unavailable", "interface_unavailable", "tool_not_found"],
        tags=["wpa3", "sae", "dragonblood", "configuration", "passive"],
    )


HOSTAPD_WPA3_AUDIT_METADATA = _metadata(
    "hostapd_wpa3_audit", "hostapd_cli - WPA3 Configuration Audit", "hostapd_cli"
)
WPA_SUPPLICANT_WPA3_AUDIT_METADATA = _metadata(
    "wpa_supplicant_wpa3_audit", "wpa_cli - WPA3 Configuration Audit", "wpa_cli"
)
WPA_SUPPLICANT_WPA3_STATUS_METADATA = ToolCapabilityMetadata(
    name="wpa_supplicant_wpa3_status",
    display_name="wpa_cli - Connected SAE Status",
    category=CapabilityCategory.WPA_ASSESSMENT,
    description="Observe the SAE group selected by an existing wpa_supplicant connection",
    tool_binary="wpa_cli",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX], interface_required=True, privileges=[]
    ),
    inputs=["interface"],
    outputs=["bssid", "key_mgmt", "sae_group", "sae_pwe", "connection_state"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.PASSIVE_OBSERVATION, persistent=False,
        estimated_duration_seconds=2, invasive=False, requires_authorization=False,
    ),
    failure_conditions=["control_socket_unavailable", "interface_unavailable", "tool_not_found"],
    tags=["wpa3", "sae", "status", "passive"],
)


def register(registry):
    registry.register(HOSTAPD_WPA3_AUDIT_METADATA, HostapdWpa3AuditAdapter)
    registry.register(WPA_SUPPLICANT_WPA3_AUDIT_METADATA, WpaSupplicantWpa3AuditAdapter)
    registry.register(WPA_SUPPLICANT_WPA3_STATUS_METADATA, WpaSupplicantStatusAuditAdapter)
