"""
Adapter for hashcat - password-recovery and credential-strength assessment.

Treated as controlled offline analysis component operating on legitimately obtained material.
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


class HashcatAdapter(ToolAdapterBase):
    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        hash_file = parameters.get("hash_file") or parameters.get("input_file")
        if not hash_file:
            raise ValueError("hash_file required for hashcat")

        cmd = ["hashcat"]

        # Mode - default 22000 for WPA PMKID/EAPOL
        mode = parameters.get("mode", "22000")
        cmd.extend(["-m", str(mode)])

        # Attack mode
        attack_mode = parameters.get("attack_mode", "0")  # 0 = dictionary
        cmd.extend(["-a", str(attack_mode)])

        # Hash file
        cmd.append(hash_file)

        # Wordlist or mask
        if parameters.get("wordlist"):
            cmd.append(parameters["wordlist"])
        elif parameters.get("mask"):
            cmd.append(parameters["mask"])
        else:
            # Default to example dicts if available, or show help
            # For safety, if no wordlist, use --help to avoid running without scope
            if not parameters.get("show_help"):
                # Require wordlist for actual execution
                raise ValueError("wordlist or mask required for hashcat")

        # Additional options
        if parameters.get("session"):
            cmd.extend(["--session", parameters["session"]])

        if parameters.get("potfile_disable"):
            cmd.append("--potfile-disable")

        return cmd

    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: str | None
    ) -> List[Evidence]:
        combined = raw_output + "\n" + error_output

        parsed = {
            "hash_file": parameters.get("hash_file") or parameters.get("input_file"),
            "mode": parameters.get("mode", "22000"),
        }

        # Parse cracked passwords
        # hashcat output often contains <hash>:<password>
        cracked = []

        # Look for cracked pattern
        for line in combined.splitlines():
            # Common pattern: hash:password
            if ":" in line and len(line.split(":")) >= 2:
                # Avoid false positives from status lines
                if "Session" in line or "Status" in line or "Hash" in line and "Target" in line:
                    continue
                # Try to extract password part after last colon for WPA
                # For WPA, format is often <bssid>:<stamac>:<essid>:<password> or similar
                # We'll capture lines that look like cracked
                if re.search(r"[0-9a-fA-F]{12,}", line) and ":" in line:
                    # Potential hash line
                    parts = line.split(":")
                    if len(parts) >= 2:
                        password = parts[-1].strip()
                        if password and len(password) < 100 and not password.startswith(" "):
                            # Heuristic: password likely not contain spaces at start and not too long
                            if "Cracked" not in line:
                                cracked.append({"raw": line.strip(), "password": password})

        # Also check for explicit cracked count
        m = re.search(r"Cracked:\s*(\d+)/\d+", combined)
        if m:
            parsed["cracked_count"] = int(m.group(1))

        if cracked:
            parsed["cracked"] = cracked
            parsed["success"] = True
        else:
            parsed["success"] = False
            # Check if hashcat says all hashes cracked or exhausted
            if "All hashes have been recovered" in combined or "Cracked" in combined:
                parsed["completed"] = True

        ev = Evidence.from_tool_output(
            tool_name="hashcat",
            capability="credential_assessment",
            evidence_type=EvidenceType.CREDENTIAL,
            raw_output=combined,
            parsed_data=parsed,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.HIGH if parsed.get("success") else ConfidenceLevel.MEDIUM,
            execution_id=self.execution_id,
            raw_command=f"hashcat -m {parsed['mode']} {parsed['hash_file']}",
        )
        return [ev]

    def custom_parameter_validation(self, parameters: Dict[str, Any]):
        errors = []
        if not parameters.get("hash_file") and not parameters.get("input_file"):
            errors.append("hash_file required")
        # For security, ensure wordlist exists if provided
        return (False, errors) if errors else (True, [])


METADATA = ToolCapabilityMetadata(
    name="hashcat",
    display_name="hashcat - Credential Strength Assessment",
    category=CapabilityCategory.CREDENTIAL_ASSESSMENT,
    description="Password-recovery and credential-strength assessment platform for offline analysis of legitimately obtained material",
    tool_binary="hashcat",
    version="1.0",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
    ),
    inputs=["hash_file", "optional_wordlist", "optional_mode", "optional_attack_mode"],
    outputs=["credential_observation"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.OFFLINE_ANALYSIS,
        persistent=False,
        estimated_duration_seconds=120,
        invasive=False,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found", "invalid_parameters"],
    tags=["cracking", "offline", "credential"],
)

ADAPTER_CLASS = HashcatAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
