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


from ...utils.redaction import redact_with_report
from ...utils.system import ensure_private_dir, tighten_file_mode


class AuditLogger:
    """Logs all assessment activities for auditability."""

    def __init__(self, log_dir: str = "/tmp/wifi_framework_audit", assessment_id: Optional[str] = None):
        self.log_dir = log_dir
        self.assessment_id = assessment_id or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.events: List[Dict[str, Any]] = []

        #: Audit writes that failed. An assessment whose trail silently stopped
        #: being recorded is not auditable, so failures are counted and surfaced
        #: rather than swallowed.
        self.write_failures: List[str] = []

        #: Secrets seen so far, accumulated across events. A passphrase is supplied
        #: when the Decision Engine parameterises an action but is written into a
        #: command line when the Execution Engine reports it, so masking has to reach
        #: across the trail rather than treat each event independently.
        self._secrets: Dict[str, set] = {}

        # Ensure the log directory exists and is readable only by this user. The
        # default sits under /tmp, which is world-writable and predictable.
        ensure_private_dir(self.log_dir)

    def log_event(self, event_type: str, data: Dict[str, Any], timestamp: Optional[datetime] = None):
        """Log an event.

        ``data`` is redacted here rather than at each call site. This is the single
        point every audit record passes through, so a new event type cannot disclose
        an operator secret by forgetting to filter - and the adapters do put secrets
        in command lines (``aircrack-ng`` a passphrase, ``reaver`` a WPS PIN,
        Impacket ``user:pass@host``). What was masked is recorded on the event, so
        the trail states that it was filtered instead of presenting a masked value
        as the value that was used.
        """
        timestamp = timestamp or datetime.now(timezone.utc)
        redacted_data, report = redact_with_report(data, known_secrets=self._secrets)
        event = {
            "timestamp": timestamp.isoformat(),
            "assessment_id": self.assessment_id,
            "event_type": event_type,
            "data": redacted_data,
        }
        if report.applied:
            event["redaction"] = report.to_dict()
        self.events.append(event)

        # Also write to file for persistence
        try:
            log_file = os.path.join(self.log_dir, f"{self.assessment_id}.jsonl")
            with open(log_file, "a") as f:
                f.write(json.dumps(event) + "\n")
            if not tighten_file_mode(log_file):
                # The event is written but the file may be readable by other local
                # users. Recorded rather than raised: abandoning the trail mid-write
                # would lose more than the permission problem costs, but the problem
                # must not be invisible either.
                self.write_failures.append(
                    f"{log_file} could not be restricted to owner-only access"
                )
        except OSError as exc:
            # Not silent: an audit trail that stops being written must be visible,
            # otherwise the assessment looks auditable and is not.
            self.write_failures.append(f"{type(exc).__name__}: {exc}")

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

    def log_contract(self, contract, *, full_payload: Optional[bool] = None, summary: Optional[Dict[str, Any]] = None):
        """
        Log an inter-engine contract message.

        Every message is recorded with its envelope (schema, version, message_id,
        correlation_id) and a payload digest, so the sequence of messages that produced a
        finding can be reconstructed even when the payload itself is too large to inline.

        Full payloads are recorded for the small, decision-bearing contracts. ``world-state``
        and ``evidence-set`` are recorded as a summary plus digest by default: their content is
        already in the audit trail as individual evidence and execution events, and inlining
        hundreds of observations per iteration would bury the trail rather than improve it.
        """
        envelope = contract.envelope().to_dict()
        digest = contract.digest()
        if full_payload is None:
            full_payload = contract.SCHEMA not in self.COMPACT_PAYLOAD_SCHEMAS

        data: Dict[str, Any] = {
            "envelope": envelope,
            "payload_digest": digest,
            "payload_recorded": bool(full_payload),
        }
        if summary:
            data["summary"] = summary
        if full_payload:
            data["payload"] = contract.payload()
        else:
            data["summary"] = summary or (
                contract.summary() if hasattr(contract, "summary") else {"schema": contract.SCHEMA}
            )
        self.log_event(f"contract:{contract.SCHEMA}", data)
        return digest

    #: Contracts recorded as summary + digest rather than full payload.
    COMPACT_PAYLOAD_SCHEMAS = frozenset({"world-state", "evidence-set"})

    def log_contract_rejection(self, action_id: str, reason: Dict[str, Any], stage: str):
        """Record that an action never ran, and why."""
        self.log_event(
            "action_rejected",
            {"action_id": action_id, "stage": stage, "reason": reason},
        )

    def log_verification(self, finding_id: str, method: str, success: bool, evidence_id: Optional[str] = None):
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
            trace : Dict[str, Any] = {
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
        report["correlation_chains"] = self.correlation_chains(state)
        report["contracts"] = self.contract_catalogue()

        return report

    @staticmethod
    def contract_catalogue() -> Dict[str, Any]:
        """The contract schemas and versions this build produces and consumes."""
        from ...contracts.registry import get_contract_registry

        return get_contract_registry().describe()

    @staticmethod
    def correlation_chains(state: AssessmentState) -> List[Dict[str, Any]]:
        """
        Reconstruct the causal chain required by specification section 17:

            assessment_id -> action_id -> execution_id -> evidence_id -> verification_id

        One entry per action, so a reader can answer "which operation produced this evidence,
        and what did the framework conclude from it" without walking the whole event log.
        """
        chains: List[Dict[str, Any]] = []
        evidence_by_execution: Dict[str, List[str]] = {}
        for evidence in state.evidences:
            if evidence.execution_id:
                evidence_by_execution.setdefault(evidence.execution_id, []).append(evidence.id)

        verifications = state.extra.get("verifications") or []
        verification_by_execution: Dict[str, List[str]] = {}
        verification_by_evidence: Dict[str, List[str]] = {}
        for entry in verifications:
            execution_id = entry.get("execution_id")
            verification_id = entry.get("verification_id")
            if execution_id and verification_id:
                verification_by_execution.setdefault(execution_id, []).append(verification_id)
            for evidence_id in entry.get("supporting_evidence") or []:
                verification_by_evidence.setdefault(evidence_id, []).append(verification_id)

        for record in state.execution_history:
            evidence_ids = record.evidence_ids or evidence_by_execution.get(record.id, [])
            verification_ids = sorted(
                set(verification_by_execution.get(record.id, []))
                | {
                    verification_id
                    for evidence_id in evidence_ids
                    for verification_id in verification_by_evidence.get(evidence_id, [])
                }
            )
            chains.append(
                {
                    "assessment_id": state.id,
                    "action_id": record.action_id,
                    "execution_id": record.id,
                    "correlation_id": record.correlation_id,
                    "capability": record.capability_name,
                    "status": record.status or ("success" if record.success else "failed"),
                    "timestamp": record.timestamp.isoformat(),
                    "evidence_ids": list(evidence_ids),
                    "verification_ids": verification_ids,
                    "artifact_ids": list(record.artifact_ids),
                    "finding_ids": sorted(
                        {
                            finding.id
                            for finding in state.findings
                            if set(finding.evidence_ids) & set(evidence_ids)
                        }
                    ),
                }
            )
        return chains

    def save_report(self, state: AssessmentState, output_path: Optional[str] = None) -> str:
        """Save report to file."""
        report = self.generate_report(state)
        if not output_path:
            output_path = os.path.join(self.log_dir, f"{state.id}_report.json")

        # The report inlines ``raw_command`` for every evidence item and every
        # finding trace, and ``parameters`` for every execution. It is the artefact
        # most likely to leave the machine it was produced on, so it is filtered on
        # the way out rather than relying on generate_report's callers.
        report, report_redaction = redact_with_report(report, known_secrets=self._secrets)
        if report_redaction.applied:
            report["redaction"] = report_redaction.to_dict()

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        return output_path
