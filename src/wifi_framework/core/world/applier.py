"""
World Model consumption of ``evidence-set`` and ``verification-result`` messages.

The Evidence Engine must not modify World Model storage directly (specification section 7), and
the Verification Engine returns a result rather than mutating findings. This module is the only
writer: it applies incoming contracts to the authoritative state and reports exactly what
changed, so a state transition is observable and reproducible (specification section 16).

Status mapping from ``verification-result`` to the finding lifecycle is explicit, because the
two enumerations are not identical:

    verified      -> FindingStatus.VERIFIED    (independent corroboration reached threshold)
    supported     -> FindingStatus.SUPPORTED   (plausible, single source)
    refuted       -> FindingStatus.REFUTED     (contradicting evidence decisive)
    contradicted  -> FindingStatus.UNRESOLVED  (conflict, neither side decisive)
    unresolved    -> FindingStatus.UNRESOLVED  (insufficient evidence)
    stale         -> FindingStatus.UNRESOLVED  (supporting evidence outside freshness window)

Demoting a ``supported`` finding to ``unresolved`` on contradiction or staleness is deliberate:
keeping it as supported would report a conclusion the framework can no longer back with current
evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from ...contracts.evidence import EvidenceSet
from ...contracts.envelope import format_timestamp
from ...contracts.verification import VerificationResult, VerificationStatus
from ..models.assessment_state import AssessmentState
from ..models.evidence import Evidence
from ..models.finding import Finding, FindingStatus


@dataclass
class ApplyReport:
    """What a contract application actually changed."""

    contract_schema: str
    accepted: int = 0
    rejected: int = 0
    added_ids: List[str] = field(default_factory=list)
    updated_ids: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    state_changed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract_schema": self.contract_schema,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "added_ids": list(self.added_ids),
            "updated_ids": list(self.updated_ids),
            "skipped": list(self.skipped),
            "notes": list(self.notes),
            "state_changed": self.state_changed,
        }


#: Explicit mapping from verification status to finding lifecycle status.
VERIFICATION_TO_FINDING_STATUS: Dict[str, FindingStatus] = {
    VerificationStatus.VERIFIED: FindingStatus.VERIFIED,
    VerificationStatus.SUPPORTED: FindingStatus.SUPPORTED,
    VerificationStatus.REFUTED: FindingStatus.REFUTED,
    VerificationStatus.CONTRADICTED: FindingStatus.UNRESOLVED,
    VerificationStatus.UNRESOLVED: FindingStatus.UNRESOLVED,
    VerificationStatus.STALE: FindingStatus.UNRESOLVED,
}


class WorldModelApplier:
    """Applies evidence and verification contracts to the assessment state."""

    def apply_evidence(
        self,
        state: AssessmentState,
        evidence_set: EvidenceSet,
        evidences: Sequence[Evidence],
    ) -> ApplyReport:
        """
        Incorporate an EvidenceSet into the World Model.

        ``evidences`` carries the model-layer objects that the contract's observations refer to.
        The contract is the record of what was extracted; the objects are what the World Model
        indexes. Pairing them here keeps the contract serialisable while avoiding a second parse
        of tool output.
        """
        report = ApplyReport(contract_schema=evidence_set.SCHEMA)
        observations_by_id = {observation.id: observation for observation in evidence_set.observations}

        for evidence in evidences:
            observation = observations_by_id.get(evidence.id)
            if observation is None:
                report.skipped.append(evidence.id)
                report.notes.append(
                    f"evidence {evidence.id} was not declared in the evidence-set and was not applied"
                )
                continue
            # Bind the correlation chain onto the record before it becomes World Model state.
            evidence.action_id = evidence_set.action_id
            evidence.correlation_id = evidence_set.correlation_id
            evidence.execution_id = evidence.execution_id or evidence_set.execution_id
            if observation.in_scope is not None and not evidence.tags:
                evidence.tags.append("in_scope" if observation.in_scope else "out_of_scope")

            already_present = any(existing.id == evidence.id for existing in state.evidences)
            if already_present:
                report.skipped.append(evidence.id)
                continue

            state.add_evidence(evidence)
            report.accepted += 1
            report.added_ids.append(evidence.id)
            report.state_changed = True

        if evidence_set.parse_issues:
            # Declared extraction problems travel with the state so they cannot be forgotten
            # when a finding is later promoted.
            report.notes.extend(f"parse_issue: {issue}" for issue in evidence_set.parse_issues)
        if evidence_set.incomplete:
            report.notes.append("evidence-set was marked incomplete by the Evidence Engine")
        return report

    def apply_execution(self, state: AssessmentState, record: Any) -> ApplyReport:
        """
        Append an execution record to the assessment history.

        Execution history is append-only: a failed run stays visible next to the successful
        ones, because the audit trail has to explain what was attempted, not only what worked.
        """
        report = ApplyReport(contract_schema="execution-record")
        if any(existing.id == record.id for existing in state.execution_history):
            report.skipped.append(record.id)
            report.notes.append(f"execution {record.id} was already recorded")
            return report
        state.add_execution(record)
        report.accepted = 1
        report.added_ids.append(record.id)
        report.state_changed = True
        return report

    def apply_verification(
        self, state: AssessmentState, result: VerificationResult
    ) -> ApplyReport:
        """Update the finding lifecycle from a VerificationResult."""
        report = ApplyReport(contract_schema=result.SCHEMA)
        targets = self._resolve_targets(state, result)

        if not targets:
            report.rejected += 1
            report.notes.append(
                f"verification {result.verification_id} references subject "
                f"{result.subject_id!r}/hypothesis {result.hypothesis_id!r} which does not exist"
            )
            return report

        new_status = VERIFICATION_TO_FINDING_STATUS.get(result.status)
        if new_status is None:
            report.rejected += 1
            report.notes.append(f"unknown verification status {result.status!r}")
            return report

        for finding in targets:
            previous = finding.status
            self._transition(finding, result, new_status)
            report.accepted += 1
            report.updated_ids.append(finding.id)
            report.state_changed = report.state_changed or previous != finding.status
            if previous != finding.status:
                report.notes.append(
                    f"finding {finding.id}: {previous.value} -> {finding.status.value} "
                    f"({result.status}, method={result.method})"
                )
        return report

    # ------------------------------------------------------------------ internals

    @staticmethod
    def _resolve_targets(state: AssessmentState, result: VerificationResult) -> List[Finding]:
        """Find the findings a verification result speaks about."""
        wanted = {identifier for identifier in (result.hypothesis_id, result.subject_id) if identifier}
        matched: List[Finding] = []
        for finding in state.findings:
            if finding.id in wanted:
                matched.append(finding)
                continue
            if result.subject_id and result.subject_id in (finding.affected_assets or []):
                matched.append(finding)
        # De-duplicate while preserving order.
        seen = set()
        unique = []
        for finding in matched:
            if finding.id not in seen:
                seen.add(finding.id)
                unique.append(finding)
        return unique

    @staticmethod
    def _transition(finding: Finding, result: VerificationResult, new_status: FindingStatus) -> None:
        details: Dict[str, Any] = dict(finding.details or {})
        verification_record = {
            "verification_id": result.verification_id,
            "status": result.status,
            "method": result.method,
            "confidence": result.confidence,
            "independent_sources": list(result.independent_sources),
            "contradicting_evidence": list(result.contradicting_evidence),
            "at": format_timestamp(datetime.now(timezone.utc)),
        }
        history = list(details.get("verification_history") or [])
        history.append(verification_record)
        details["verification_history"] = history

        if result.status == VerificationStatus.VERIFIED:
            # ``Finding.verify`` records the independent evidence and raises confidence; use it
            # so the model-layer invariant (verified implies corroboration) stays in one place.
            corroborating = next(
                (eid for eid in result.supporting_evidence if eid not in finding.verification_evidence_ids),
                result.supporting_evidence[0] if result.supporting_evidence else "",
            )
            if corroborating:
                finding.verify(corroborating, method=result.method or "verification_engine")
            else:
                finding.status = FindingStatus.VERIFIED
                finding.verification_method = result.method
                finding.verified_at = datetime.now(timezone.utc)
        elif result.status == VerificationStatus.SUPPORTED:
            for evidence_id in result.supporting_evidence:
                finding.add_evidence(evidence_id)
            finding.status = FindingStatus.SUPPORTED
            finding.verification_method = result.method
        elif result.status == VerificationStatus.REFUTED:
            finding.refute(reason=result.conclusion.details.get("reason", "") if result.conclusion else "")
        else:
            finding.status = new_status

        finding.confidence = float(result.confidence)
        for evidence_id in result.supporting_evidence:
            finding.add_evidence(evidence_id)
        if result.conclusion and result.conclusion.details:
            details["verification_details"] = result.conclusion.details
        if result.status in (VerificationStatus.CONTRADICTED, VerificationStatus.STALE, VerificationStatus.UNRESOLVED):
            details["verification_blocker"] = result.status
            if result.required_evidence:
                details["required_evidence"] = [item.to_dict() for item in result.required_evidence]
        finding.details = details
        finding.updated_at = datetime.now(timezone.utc)
