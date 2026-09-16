"""
Audit logger - every meaningful assessment action should be reconstructable
from recorded execution history.

Records scope, discovered capabilities, selected actions, generated parameters,
execution results, observations, verification operations, state transitions, final findings.

Resulting report should explain not only what was discovered, but also which real
observation produced evidence, which operation generated it, when it occurred,
and how framework verified or qualified conclusion.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..models.assessment_state import AssessmentState, ExecutionRecord
from ..models.evidence import Evidence
from ..models.finding import Finding


class AuditLogger:
    """Logs all assessment activities for auditability."""

    def __init__(self, log_dir: str = "/tmp/wifi_framework_audit", assessment_id: str = None):
        self.log_dir = log_dir
        self.assessment_id = assessment_id or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.events: List[Dict[str, Any]] = []

        # Ensure log dir exists
        os.makedirs(self.log_dir, exist_ok=True)

    def log_event(self, event_type: str, data: Dict[str, Any], timestamp: datetime = None):
        """Log an event."""
        timestamp = timestamp or datetime.now(timezone.utc)
        event = {
            "timestamp": timestamp.isoformat(),
            "assessment_id": self.assessment_id,
            "event_type": event_type,
            "data": data,
        }
        self.events.append(event)

        # Also write to file for persistence
        try:
            log_file = os.path.join(self.log_dir, f"{self.assessment_id}.jsonl")
            with open(log_file, "a") as f:
                f.write(json.dumps(event) + "\n")
        except OSError:
            pass

    def log_scope(self, scope):
        self.log_event("scope_defined", {"scope": scope.to_dict()})

    def log_capability_discovery(self, available: Dict, unavailable: Dict):
        self.log_event(
            "capability_discovery",
            {
                "available_count": len(available),
                "unavailable_count": len(unavailable),
                "available": list(available.keys()),
                "unavailable": unavailable,
            },
        )

    def log_action_selection(self, action: Dict[str, Any]):
        self.log_event(
            "action_selected",
            {
                "capability": action.get("capability_name"),
                "interface": action.get("interface"),
                "parameters": action.get("parameters"),
                "uncertainty": action.get("uncertainty"),
                "score": action.get("score"),
                "reason": action.get("reason"),
            },
        )

    def log_execution(self, record: ExecutionRecord):
        self.log_event("execution", record.to_dict())

    def log_evidence(self, evidence: Evidence):
        self.log_event(
            "evidence",
            {
                "evidence_id": evidence.id,
                "type": evidence.evidence_type.value,
                "source": {
                    "tool": evidence.source.tool_name,
                    "capability": evidence.source.capability,
                },
                "parsed_data": evidence.parsed_data,
                "confidence": evidence.confidence,
                "interface": evidence.interface,
            },
        )

    def log_finding(self, finding: Finding):
        self.log_event("finding", finding.to_dict())

    def log_state_transition(self, from_phase: str, to_phase: str, reason: str = ""):
        self.log_event(
            "phase_transition",
            {"from": from_phase, "to": to_phase, "reason": reason},
        )

    def log_verification(self, finding_id: str, method: str, success: bool, evidence_id: str = None):
        self.log_event(
            "verification",
            {
                "finding_id": finding_id,
                "method": method,
                "success": success,
                "evidence_id": evidence_id,
            },
        )

    def generate_report(self, state: AssessmentState) -> Dict[str, Any]:
        """Generate audit report explaining what was discovered and how."""
        report = {
            "assessment_id": state.id,
            "created_at": state.created_at.isoformat(),
            "updated_at": state.updated_at.isoformat(),
            "scope": state.scope.to_dict(),
            "summary": state.summary(),
            "execution_history": [r.to_dict() for r in state.execution_history],
            "evidences": [
                {
                    "id": e.id,
                    "timestamp": e.timestamp.isoformat(),
                    "type": e.evidence_type.value,
                    "source_tool": e.source.tool_name,
                    "source_capability": e.source.capability,
                    "interface": e.interface,
                    "parsed_data": e.parsed_data,
                    "confidence": e.confidence,
                    "execution_id": e.execution_id,
                    "raw_command": e.source.raw_command,
                }
                for e in state.evidences
            ],
            "findings": [f.to_dict() for f in state.findings],
            "world_model": state.world_model.to_dict(),
            "phase_transitions": state.extra.get("phase_transitions", []),
            "audit_events_count": len(self.events),
        }

        # Add traceability: for each finding, show which evidence produced it
        finding_traces = []
        for finding in state.findings:
            trace = {
                "finding_id": finding.id,
                "title": finding.title,
                "status": finding.status.value,
                "evidence_chain": [],
            }
            for ev_id in finding.evidence_ids:
                ev = next((e for e in state.evidences if e.id == ev_id), None)
                if ev:
                    trace["evidence_chain"].append(
                        {
                            "evidence_id": ev.id,
                            "timestamp": ev.timestamp.isoformat(),
                            "tool": ev.source.tool_name,
                            "capability": ev.source.capability,
                            "raw_command": ev.source.raw_command,
                            "parsed_data": ev.parsed_data,
                        }
                    )
            finding_traces.append(trace)

        report["finding_traces"] = finding_traces

        return report

    def save_report(self, state: AssessmentState, output_path: str = None) -> str:
        """Save report to file."""
        report = self.generate_report(state)
        if not output_path:
            output_path = os.path.join(self.log_dir, f"{state.id}_report.json")

        try:
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2)
        except OSError as e:
            raise

        return output_path
