"""
``experience-record`` contract (version 1.0).

Producer: Experience layer. Consumers: Experience layer and Decision Engine.

A normalized record of one completed action: the state it was taken in, what was requested,
what happened, what was observed, whether verification supported the conclusion, and what it
cost. ``state_before`` / ``state_after`` are digests of the ``world-state`` message rather than
embedded copies, which keeps records small while still identifying the exact transition.

The specification is explicit that experience storage must not become a hidden source of
truth: the World Model remains authoritative for the current assessment state, and a Decision
Engine that consults experience is consulting a heuristic prior, not a fact. That is why
``outcome.information_gain`` is normalized to ``[0, 1]`` — it is a comparable score for
ranking future actions, not a measurement of the environment.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .base import BaseContract
from .common import to_jsonable
from .envelope import EngineId
from .validation import (
    ValidationIssue,
    ValidationLevel,
    require_confidence,
    require_type,
)


@dataclass(frozen=True)
class ExecutionOutcomeCost:
    """What the action cost."""

    duration_ms: int = 0
    #: Number of real subprocess invocations, including prerequisite probes.
    tool_invocations: int = 1
    #: Bytes of captured output/artifacts, when known.
    bytes_collected: int = 0
    #: True when the action needed root privileges to run.
    required_root: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return to_jsonable(self.__dict__)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "ExecutionOutcomeCost":
        data = data or {}
        return cls(
            duration_ms=int(data.get("duration_ms") or 0),
            tool_invocations=int(data.get("tool_invocations") or 0),
            bytes_collected=int(data.get("bytes_collected") or 0),
            required_root=bool(data.get("required_root", False)),
        )

    @classmethod
    def from_execution(cls, execution: Any) -> "ExecutionOutcomeCost":
        """
        Derive the cost of an action from its ``execution-result``.

        Accepts the contract object or its payload dict so either side of the pipeline can
        report cost without importing this module's producer. Prerequisite probes are real
        subprocess invocations and are counted as such.
        """
        data = execution.payload() if hasattr(execution, "payload") else dict(execution or {})
        artifacts = data.get("artifacts") or []
        bytes_collected = sum(int((a.get("bytes") or 0)) for a in artifacts if isinstance(a, dict))
        prerequisites = data.get("prerequisites") or []
        return cls(
            duration_ms=int(data.get("duration_ms") or 0),
            tool_invocations=1 + len(prerequisites),
            bytes_collected=bytes_collected,
            required_root=bool(data.get("required_root", False)),
        )


@dataclass(frozen=True)
class ActionOutcome:
    """The normalized outcome of one action."""

    #: Comparable usefulness score in ``[0, 1]``; see ``ExperienceEngine`` for the computation.
    information_gain: float = 0.0
    useful: bool = False
    cost: ExecutionOutcomeCost = field(default_factory=ExecutionOutcomeCost)
    #: Observations that were new to the World Model (not already known).
    new_observations: int = 0
    #: Uncertainties closed by this action.
    gaps_closed: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "information_gain": self.information_gain,
            "useful": self.useful,
            "cost": self.cost.to_dict(),
            "new_observations": self.new_observations,
            "gaps_closed": list(self.gaps_closed),
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "ActionOutcome":
        data = data or {}
        return cls(
            information_gain=float(data.get("information_gain") or 0.0),
            useful=bool(data.get("useful", False)),
            cost=ExecutionOutcomeCost.from_dict(data.get("cost")),
            new_observations=int(data.get("new_observations") or 0),
            gaps_closed=list(data.get("gaps_closed") or []),
        )


@dataclass(kw_only=True)
class ExperienceRecord(BaseContract):
    """One normalized experience entry."""

    SCHEMA = "experience-record"
    VERSION = "1.0"
    PRODUCER = EngineId.EXPERIENCE.value
    REQUIRED_PAYLOAD_FIELDS = ("record_id", "state_before", "state_after", "action", "execution", "outcome")

    record_id: str
    #: Digest of the ``world-state`` message before the action.
    state_before: str
    #: Digest of the ``world-state`` message after the action.
    state_after: str
    #: The ``action-request`` payload as sent.
    action: Dict[str, Any] = field(default_factory=dict)
    #: The ``execution-result`` payload as returned.
    execution: Dict[str, Any] = field(default_factory=dict)
    #: Observation summaries from the ``evidence-set``.
    observations: List[Dict[str, Any]] = field(default_factory=list)
    #: The ``verification-result`` payload, when verification ran.
    verification: Dict[str, Any] = field(default_factory=dict)
    outcome: ActionOutcome = field(default_factory=ActionOutcome)

    #: Optional extensions for heuristic ranking -----------------------------
    capability: Optional[str] = None
    tool: Optional[str] = None
    interface: Optional[str] = None
    uncertainty_type: Optional[str] = None
    action_id: Optional[str] = None
    execution_id: Optional[str] = None
    #: World Model revision the record was taken against.
    state_revision: Optional[int] = None

    @classmethod
    def _coerce_payload(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        coerced = dict(payload)
        if isinstance(coerced.get("outcome"), dict):
            coerced["outcome"] = ActionOutcome.from_dict(coerced["outcome"])
        return coerced

    def extra_structural_issues(self, payload: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        for name in ("action", "execution", "verification"):
            issues.extend(require_type(payload, name, dict))
        issues.extend(require_type(payload, "observations", list))
        outcome = payload.get("outcome")
        outcome_dict = outcome.to_dict() if isinstance(outcome, ActionOutcome) else dict(outcome or {})
        issues.extend(require_confidence(outcome_dict, "information_gain"))
        for name in ("state_before", "state_after"):
            value = payload.get(name)
            if isinstance(value, str) and value and len(value) < 16:
                issues.append(
                    ValidationIssue(
                        level=ValidationLevel.STRUCTURAL.value,
                        code="invalid_digest",
                        message=f"'{name}' must be a state digest, got {value!r}",
                        field=name,
                    )
                )
        return issues

    @property
    def state_changed(self) -> bool:
        return self.state_before != self.state_after
