"""
Experience Engine: produces ``experience-record`` contracts.

One record per completed action, describing the state it was taken in, what was requested, what
happened, what was observed, whether verification supported the conclusion, and what it cost.
``state_before`` / ``state_after`` are digests of the ``world-state`` messages published either
side of the action, so the record identifies the exact transition without embedding the state.

Information gain is a normalized ``[0, 1]`` heuristic prior, not a measurement:

    gain = saturation(new_observations) * status_factor * verification_factor
    saturation(n) = n / (n + 1)

``saturation`` rewards new observations with diminishing returns, so an action that returns 500
duplicate beacons does not outrank one that closes a real gap. ``status_factor`` discounts
failed and partial runs. ``verification_factor`` keeps refutations valuable - learning that a
hypothesis is wrong is information - while discounting conclusions that could not be reached.

The record is also written to the pre-existing :class:`ExperienceStore`, which the action
selector consults for heuristic scoring. Experience never becomes a source of truth about the
environment: the World Model remains authoritative (specification section 12).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from ...contracts.action import ActionRequest
from ...contracts.evidence import EvidenceSet
from ...contracts.envelope import EngineId
from ...contracts.execution import ExecutionResult, ExecutionStatus
from ...contracts.experience import ActionOutcome, ExecutionOutcomeCost, ExperienceRecord
from ...contracts.verification import VerificationResult, VerificationStatus

#: Weight applied to the gain of an action, by execution status.
STATUS_FACTORS: Dict[str, float] = {
    ExecutionStatus.SUCCESS: 1.0,
    ExecutionStatus.PARTIAL: 0.7,
    ExecutionStatus.FAILED: 0.2,
    ExecutionStatus.TIMEOUT: 0.2,
    ExecutionStatus.CANCELLED: 0.1,
    ExecutionStatus.UNSUPPORTED: 0.0,
    ExecutionStatus.REJECTED: 0.0,
}

#: Weight applied once verification has judged the resulting claim.
VERIFICATION_FACTORS: Dict[str, float] = {
    VerificationStatus.VERIFIED: 1.0,
    VerificationStatus.SUPPORTED: 0.9,
    VerificationStatus.REFUTED: 0.9,
    VerificationStatus.CONTRADICTED: 0.7,
    VerificationStatus.STALE: 0.5,
    VerificationStatus.UNRESOLVED: 0.6,
}


def saturation(count: int) -> float:
    """Diminishing-returns normalization of a count into ``[0, 1)``."""
    if count <= 0:
        return 0.0
    return count / (count + 1.0)


@dataclass
class ExperienceOutcome:
    """The contract plus the values the legacy store needs, computed once."""

    record: ExperienceRecord
    information_gain: float
    useful: bool
    new_observations: int
    gaps_closed: List[str]


class ExperienceEngine:
    """Builds experience records from the contracts a completed action produced."""

    def __init__(self, store: Any = None) -> None:
        self.store = store

    def record(
        self,
        action: ActionRequest,
        execution: ExecutionResult,
        *,
        evidence_set: Optional[EvidenceSet] = None,
        verification: Optional[VerificationResult] = None,
        state_before: str = "",
        state_after: str = "",
        state_revision: Optional[int] = None,
        new_observations: Optional[int] = None,
        gaps_closed: Optional[Sequence[str]] = None,
        required_root: bool = False,
    ) -> ExperienceOutcome:
        """Assemble one ``experience-record`` and mirror it into the legacy store."""
        if evidence_set is not None:
            observations = len(evidence_set.observations)
        else:
            observations = 0
        if new_observations is None:
            new_observations = observations
        closed = [str(gap) for gap in (gaps_closed or [])]

        status_factor = STATUS_FACTORS.get(execution.status, 0.5)
        verification_factor = (
            VERIFICATION_FACTORS.get(verification.status, 0.6) if verification is not None else 1.0
        )
        gain = round(saturation(new_observations) * status_factor * verification_factor, 6)
        useful = gain > 0.0 or execution.status in ExecutionStatus.TERMINAL_EXECUTED and bool(closed)

        bytes_collected = sum(artifact.bytes for artifact in execution.artifacts)
        outcome = ActionOutcome(
            information_gain=gain,
            useful=bool(useful),
            cost=ExecutionOutcomeCost(
                duration_ms=int(execution.duration_ms),
                tool_invocations=1 if execution.status in ExecutionStatus.TERMINAL_EXECUTED else 0,
                bytes_collected=bytes_collected,
                required_root=bool(required_root),
            ),
            new_observations=int(new_observations),
            gaps_closed=closed,
        )

        record = ExperienceRecord(
            assessment_id=execution.assessment_id,
            source_engine=EngineId.EXPERIENCE.value,
            correlation_id=execution.correlation_id,
            record_id=f"{action.action_id}:{execution.execution_id}",
            state_before=state_before or "0" * 64,
            state_after=state_after or "0" * 64,
            action=action.payload(),
            execution=execution.payload(),
            observations=[
                observation.to_dict() for observation in (evidence_set.observations if evidence_set else [])
            ],
            verification=verification.payload() if verification is not None else {},
            outcome=outcome,
            capability=action.capability,
            tool=execution.tool.name if execution.tool else None,
            interface=execution.interface.name if execution.interface else None,
            uncertainty_type=action.reason.uncertainty_type,
            action_id=action.action_id,
            execution_id=execution.execution_id,
            state_revision=state_revision,
        )

        self._mirror_to_store(action, execution, record, new_observations, verification)
        return ExperienceOutcome(
            record=record,
            information_gain=gain,
            useful=bool(useful),
            new_observations=new_observations,
            gaps_closed=closed,
        )

    # ------------------------------------------------------------------ internals

    def _mirror_to_store(
        self,
        action: ActionRequest,
        execution: ExecutionResult,
        record: ExperienceRecord,
        new_observations: int,
        verification: Optional[VerificationResult],
    ) -> None:
        """
        Keep the pre-existing heuristic store in sync.

        The store's own scoring remains the input to action selection; this method only feeds
        it. If no store is configured the contract is still produced and audited.
        """
        if self.store is None:
            return
        self.store.add(
            capability_name=execution.implementation or action.capability,
            tool_binary=execution.tool.name if execution.tool else "",
            interface=execution.interface.name if execution.interface else None,
            parameters=dict(action.parameters or {}),
            state_summary={
                "state_before": record.state_before,
                "state_after": record.state_after,
                "revision": record.state_revision,
            },
            uncertainty_type=action.reason.uncertainty_type,
            success=execution.succeeded,
            exit_code=execution.exit_code,
            duration_seconds=execution.duration_ms / 1000.0,
            evidence_count=new_observations,
            failure_reason=execution.failure.message if execution.failure else None,
        )
        if verification is not None:
            self.store.update_verification(
                execution.implementation or action.capability,
                verification.status in VerificationStatus.POSITIVE,
            )
