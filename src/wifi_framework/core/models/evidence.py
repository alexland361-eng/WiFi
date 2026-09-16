"""
Evidence model - structured representation of observations from real tool execution.

Every raw command output is parsed into structured evidence containing identifiers,
timestamps, sources, parameters, and confidence information.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class EvidenceType(str, Enum):
    """Types of evidence that can be collected."""
    INTERFACE = "interface"
    ACCESS_POINT = "access_point"
    CLIENT = "client"
    SIGNAL = "signal_observation"
    CHANNEL = "channel"
    AUTHENTICATION = "authentication_observation"
    WPS = "wps_observation"
    CAPTURE = "capture"
    HANDSHAKE = "handshake"
    NETWORK_HOST = "network_host"
    NETWORK_SERVICE = "network_service"
    DNS = "dns_observation"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential_observation"
    RADIO_BLOCK = "radio_block"
    DRIVER_INFO = "driver_info"
    GENERIC = "generic"


class ConfidenceLevel(float, Enum):
    """Confidence levels for evidence."""
    LOW = 0.3
    MEDIUM = 0.6
    HIGH = 0.85
    VERIFIED = 0.95


@dataclass(frozen=True)
class EvidenceSource:
    """Source of evidence - which tool and capability produced it."""
    tool_name: str
    capability: str
    adapter_version: str = "1.0"
    interface: Optional[str] = None
    raw_command: Optional[str] = None


@dataclass
class Evidence:
    """
    Structured evidence from a real tool execution.

    This is the fundamental unit that the world model uses to build understanding.
    Raw output is never treated as authoritative finding by itself.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_type: EvidenceType = EvidenceType.GENERIC
    source: EvidenceSource = field(default_factory=lambda: EvidenceSource(tool_name="unknown", capability="unknown"))
    parameters: Dict[str, Any] = field(default_factory=dict)
    raw_output: Optional[str] = None
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    confidence: float = ConfidenceLevel.MEDIUM
    interface: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    # For auditability
    execution_id: Optional[str] = None

    def __post_init__(self):
        # Validate confidence bounds
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0 and 1, got {self.confidence}")
        # Ensure timestamp is timezone aware
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for serialization / audit logging."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "evidence_type": self.evidence_type.value,
            "source": {
                "tool_name": self.source.tool_name,
                "capability": self.source.capability,
                "adapter_version": self.source.adapter_version,
                "interface": self.source.interface,
                "raw_command": self.source.raw_command,
            },
            "parameters": self.parameters,
            "parsed_data": self.parsed_data,
            "confidence": self.confidence,
            "interface": self.interface,
            "tags": self.tags,
            "execution_id": self.execution_id,
            # raw_output intentionally excluded from default dict for size, but available
        }

    @classmethod
    def from_tool_output(
        cls,
        tool_name: str,
        capability: str,
        evidence_type: EvidenceType,
        raw_output: str,
        parsed_data: Dict[str, Any],
        parameters: Dict[str, Any],
        interface: Optional[str] = None,
        confidence: float = ConfidenceLevel.MEDIUM,
        execution_id: Optional[str] = None,
        raw_command: Optional[str] = None,
    ) -> "Evidence":
        """Factory for creating evidence from tool execution."""
        source = EvidenceSource(
            tool_name=tool_name,
            capability=capability,
            interface=interface,
            raw_command=raw_command,
        )
        return cls(
            evidence_type=evidence_type,
            source=source,
            parameters=parameters,
            raw_output=raw_output,
            parsed_data=parsed_data,
            confidence=confidence,
            interface=interface,
            execution_id=execution_id,
        )
