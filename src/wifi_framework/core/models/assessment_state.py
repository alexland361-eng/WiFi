"""
Assessment state - central state machine for adaptive assessment.

Distinguishes between observations, hypotheses, supported findings, verified findings,
and refuted or unresolved hypotheses.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from .capability import ToolCapabilityMetadata
from .evidence import Evidence
from .finding import Finding, FindingStatus
from .scope import AssessmentScope
from .world_model import WorldModel


class AssessmentPhase(str, Enum):
    INITIALIZING = "initializing"
    INTERFACE_DISCOVERY = "interface_discovery"
    CAPABILITY_DISCOVERY = "capability_discovery"
    WIRELESS_OBSERVATION = "wireless_observation"
    ASSET_IDENTIFICATION = "asset_identification"
    WPS_ASSESSMENT = "wps_assessment"
    AUTHENTICATION_ASSESSMENT = "authentication_assessment"
    NETWORK_DISCOVERY = "network_discovery"
    SERVICE_ENUMERATION = "service_enumeration"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    VERIFICATION = "verification"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class InterfaceInfo:
    name: str
    type: str  # e.g., managed, monitor, etc.
    driver: Optional[str] = None
    chipset: Optional[str] = None
    mac: Optional[str] = None
    supports_monitor: bool = False
    supports_injection: bool = False
    is_up: bool = False
    frequency: Optional[int] = None
    channel: Optional[int] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionRecord:
    """Record of a single tool execution."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    capability_name: str = ""
    tool_binary: str = ""
    interface: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    raw_command: str = ""
    exit_code: Optional[int] = None
    duration_seconds: float = 0.0
    success: bool = False
    raw_output: Optional[str] = None
    error_output: Optional[str] = None
    evidence_ids: List[str] = field(default_factory=list)
    failure_reason: Optional[str] = None
    # For experience learning
    information_gain: float = 0.0
    cost: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "capability_name": self.capability_name,
            "tool_binary": self.tool_binary,
            "interface": self.interface,
            "parameters": self.parameters,
            "raw_command": self.raw_command,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "success": self.success,
            "evidence_ids": self.evidence_ids,
            "failure_reason": self.failure_reason,
            "information_gain": self.information_gain,
            "cost": self.cost,
        }


@dataclass
class AssessmentState:
    """
    Central assessment state.

    Maintains:
    - scope
    - discovered capabilities
    - selected actions
    - generated parameters
    - execution results
    - observations
    - verification operations
    - state transitions
    - final findings
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    phase: AssessmentPhase = AssessmentPhase.INITIALIZING

    scope: AssessmentScope = field(default_factory=AssessmentScope)
    world_model: WorldModel = field(default_factory=WorldModel)

    # Discovery
    interfaces: Dict[str, InterfaceInfo] = field(default_factory=dict)
    available_capabilities: Dict[str, ToolCapabilityMetadata] = field(default_factory=dict)
    unavailable_capabilities: Dict[str, str] = field(default_factory=dict)  # name -> reason

    # Evidence and findings
    evidences: List[Evidence] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    # Execution history
    execution_history: List[ExecutionRecord] = field(default_factory=list)

    # Planning
    uncertainties: List[Dict[str, Any]] = field(default_factory=list)
    objectives: List[str] = field(default_factory=list)

    # Metadata
    tags: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def add_evidence(self, evidence: Evidence):
        self.evidences.append(evidence)
        self.world_model.update(evidence)
        self.updated_at = datetime.now(timezone.utc)

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        self.updated_at = datetime.now(timezone.utc)

    def add_execution(self, record: ExecutionRecord):
        self.execution_history.append(record)
        self.updated_at = datetime.now(timezone.utc)

    def get_findings_by_status(self, status: FindingStatus) -> List[Finding]:
        return [f for f in self.findings if f.status == status]

    def get_evidence_by_type(self, evidence_type) -> List[Evidence]:
        return [e for e in self.evidences if e.evidence_type == evidence_type]

    def transition_phase(self, new_phase: AssessmentPhase, reason: str = ""):
        old_phase = self.phase
        self.phase = new_phase
        self.updated_at = datetime.now(timezone.utc)
        # Record phase transition as extra metadata
        if "phase_transitions" not in self.extra:
            self.extra["phase_transitions"] = []
        self.extra["phase_transitions"].append({
            "from": old_phase.value,
            "to": new_phase.value,
            "timestamp": self.updated_at.isoformat(),
            "reason": reason,
        })

    def summary(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "phase": self.phase.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "scope": self.scope.to_dict(),
            "world_model_summary": self.world_model.summary(),
            "interfaces_count": len(self.interfaces),
            "available_capabilities_count": len(self.available_capabilities),
            "unavailable_capabilities_count": len(self.unavailable_capabilities),
            "evidences_count": len(self.evidences),
            "findings_count": len(self.findings),
            "findings_by_status": {
                status.value: len(self.get_findings_by_status(status))
                for status in FindingStatus
            },
            "execution_history_count": len(self.execution_history),
            "uncertainties_count": len(self.uncertainties),
            "objectives": self.objectives,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "phase": self.phase.value,
            "scope": self.scope.to_dict(),
            "world_model": self.world_model.to_dict(),
            "interfaces": {name: iface.__dict__ for name, iface in self.interfaces.items()},
            "available_capabilities": {name: cap.to_dict() for name, cap in self.available_capabilities.items()},
            "unavailable_capabilities": self.unavailable_capabilities,
            "evidences": [e.to_dict() for e in self.evidences],
            "findings": [f.to_dict() for f in self.findings],
            "execution_history": [r.to_dict() for r in self.execution_history],
            "uncertainties": self.uncertainties,
            "objectives": self.objectives,
            "tags": self.tags,
            "extra": self.extra,
        }
