"""
``planning-context`` and ``decision-proposal`` contracts (version 1.0).

Producer of ``planning-context``: World/Decision layer. Consumer: AI Engine.
Producer of ``decision-proposal``: AI Engine. Consumer: Decision Engine.

The AI layer receives a deliberately constrained representation of the current state and
returns a **proposal**, never an executable command. Specification section 13 fixes the path a
proposal must travel before anything runs:

    AI Proposal -> Schema Validation -> Scope Validation -> Capability Validation
                -> Parameter Validation -> ActionRequest -> Execution

That path is enforced structurally here in two ways:

1. ``DecisionProposal`` has no field in which a shell command could be expressed. It can name
   a capability, a target and structured parameters, and nothing else.
2. :meth:`DecisionProposal.to_action_request` is the only conversion, and it produces an
   ordinary ``ActionRequest`` whose ``origin`` is ``ai_proposal`` — which the policy layer
   validates exactly like any planner-produced request.

The AI layer is optional. The deterministic planner implements the same producer role, so the
assessment engine remains operational, inspectable and testable when no AI model is available.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .action import ActionObjective, ActionOrigin, ActionReason, ActionRequest
from .base import BaseContract
from .common import EntityRef, TargetType, to_jsonable
from .envelope import EngineId
from .validation import (
    ValidationIssue,
    ValidationLevel,
    require_confidence,
    require_type,
)


@dataclass(kw_only=True)
class PlanningContext(BaseContract):
    """The constrained view of the assessment handed to an AI planner."""

    SCHEMA = "planning-context"
    VERSION = "1.0"
    PRODUCER = EngineId.DECISION.value
    REQUIRED_PAYLOAD_FIELDS = ("objective", "relevant_state")

    objective: Dict[str, Any] = field(default_factory=dict)
    #: A projection of the WorldState, limited to what is relevant to the objective.
    relevant_state: Dict[str, Any] = field(default_factory=dict)
    information_gaps: List[Dict[str, Any]] = field(default_factory=list)
    available_capabilities: List[Dict[str, Any]] = field(default_factory=list)
    relevant_experience: List[Dict[str, Any]] = field(default_factory=list)

    #: Constraints the proposal must respect; the policy layer enforces them regardless.
    constraints: Dict[str, Any] = field(default_factory=dict)
    #: World Model revision this context was projected from.
    state_revision: Optional[int] = None

    def extra_structural_issues(self, payload: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        for name in ("objective", "relevant_state", "constraints"):
            issues.extend(require_type(payload, name, dict))
        for name in ("information_gaps", "available_capabilities", "relevant_experience"):
            issues.extend(require_type(payload, name, list))
        return issues

    def capability_names(self) -> List[str]:
        return sorted({str(item.get("name")) for item in self.available_capabilities if item.get("name")})


@dataclass(kw_only=True)
class DecisionProposal(BaseContract):
    """An AI (or alternative planner) proposal for the next action."""

    SCHEMA = "decision-proposal"
    VERSION = "1.0"
    PRODUCER = EngineId.AI.value
    REQUIRED_PAYLOAD_FIELDS = ("capability", "reasoning_summary")

    capability: str
    target: EntityRef = field(default_factory=lambda: EntityRef(type=TargetType.NONE.value))
    parameters: Dict[str, Any] = field(default_factory=dict)
    reasoning_summary: str = ""
    confidence: float = 0.5

    #: Optional extensions ---------------------------------------------------
    objective: str = ActionObjective.RESOLVE_INFORMATION_GAP
    implementation: Optional[str] = None
    interface: Optional[str] = None
    #: Information gaps the proposal claims to close (validated against the WorldState).
    information_gaps: List[str] = field(default_factory=list)
    expected_outputs: List[str] = field(default_factory=list)
    verification_required: bool = False
    timeout_seconds: Optional[int] = None
    #: Identifier of the planner implementation, for auditability.
    planner: str = "unknown"

    @classmethod
    def _coerce_payload(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        coerced = dict(payload)
        if isinstance(coerced.get("target"), dict):
            coerced["target"] = EntityRef.from_dict(coerced["target"])
        return coerced

    def extra_structural_issues(self, payload: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        issues.extend(require_confidence(payload, "confidence"))
        issues.extend(require_type(payload, "parameters", dict))
        # The hard structural guarantee of section 13: a proposal cannot express a command.
        for forbidden in ("command", "shell", "argv", "script", "raw_command"):
            if forbidden in payload:
                issues.append(
                    ValidationIssue(
                        level=ValidationLevel.STRUCTURAL.value,
                        code="forbidden_field",
                        message=(
                            f"field '{forbidden}' is not permitted in a decision-proposal; "
                            "the AI layer cannot invoke an operating-system shell through this contract"
                        ),
                        field=forbidden,
                    )
                )
        return issues

    def to_action_request(
        self,
        *,
        action_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        source_engine: str = EngineId.DECISION.value,
    ) -> ActionRequest:
        """
        Convert an accepted proposal into an ordinary ``ActionRequest``.

        The result still has to pass scope, capability and parameter validation; this method
        performs no authorisation check of its own.
        """
        kwargs: Dict[str, Any] = {
            "assessment_id": self.assessment_id,
            "action_id": action_id or str(uuid.uuid4()),
            "capability": self.capability,
            "objective": self.objective,
            "target": self.target,
            "parameters": dict(self.parameters),
            "expected_outputs": list(self.expected_outputs),
            "verification_required": self.verification_required,
            "reason": ActionReason(
                information_gaps=list(self.information_gaps),
                summary=self.reasoning_summary,
                score=self.confidence,
            ),
            "implementation": self.implementation,
            "interface": self.interface,
            "timeout_seconds": self.timeout_seconds,
            "origin": ActionOrigin.AI_PROPOSAL,
            "source_engine": source_engine,
        }
        if correlation_id:
            kwargs["correlation_id"] = correlation_id
        return ActionRequest(**kwargs)
