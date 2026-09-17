"""
``action-request`` and ``action-validation-result`` contracts (version 1.0).

Producer of ``action-request``: Decision Engine. Consumer: Policy layer, then Execution.
Producer of ``action-validation-result``: Policy/Capability layer. Consumer: Execution.

The Decision Engine never submits a shell command. It requests a *capability* and optionally
names the registered implementation it selected; the Execution Engine remains responsible for
turning that into a concrete invocation of a real tool. Parameters are therefore either
decision hints or, after ``ExecutionGateway.prepare()``, the concrete validated values.

Specification section 9 states that a ``VerificationActionRequest`` "uses the same action
contract as ordinary planning". That is implemented literally here: it is an ``ActionRequest``
whose ``objective`` is ``resolve_verification_requirement`` and which carries the
``verification_id`` it answers to, produced by :meth:`ActionRequest.for_verification`. The
Verification Engine returns such a request to the Decision Engine instead of executing tools.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .base import BaseContract
from .common import EntityRef, TargetType, to_jsonable
from .envelope import EngineId
from .validation import (
    ValidationIssue,
    ValidationLevel,
    require_confidence,
    require_enum,
    require_type,
)


class ActionObjective:
    """Objectives a Decision Engine may pursue. Closed set, referenced by audit reports."""

    #: Ordinary planning: close an information gap identified in the WorldState.
    RESOLVE_INFORMATION_GAP = "resolve_information_gap"
    #: Answer a VerificationActionRequest from the Verification Engine.
    RESOLVE_VERIFICATION_REQUIREMENT = "resolve_verification_requirement"
    #: Confirm or refute an existing hypothesis with independent evidence.
    VERIFY_FINDING = "verify_finding"
    #: Environment discovery performed before any target-specific work.
    DISCOVER_INTERFACES = "discover_interfaces"
    DISCOVER_CAPABILITIES = "discover_capabilities"
    #: Explicitly requested by the operator through the CLI.
    OPERATOR_DIRECTED = "operator_directed"

    ALL: List[str] = [
        RESOLVE_INFORMATION_GAP,
        RESOLVE_VERIFICATION_REQUIREMENT,
        VERIFY_FINDING,
        DISCOVER_INTERFACES,
        DISCOVER_CAPABILITIES,
        OPERATOR_DIRECTED,
    ]


class ActionOrigin:
    """Who caused this action to be requested."""

    PLANNER = "planner"
    VERIFICATION = "verification"
    OPERATOR = "operator"
    #: A DecisionProposal produced by the optional AI layer, after validation.
    AI_PROPOSAL = "ai_proposal"

    ALL: List[str] = [PLANNER, VERIFICATION, OPERATOR, AI_PROPOSAL]


@dataclass(frozen=True)
class ActionReason:
    """Why the Decision Engine selected this action."""

    information_gaps: List[str] = field(default_factory=list)
    supporting_evidence: List[str] = field(default_factory=list)
    #: Free-text rationale, mirrored from the action selector's scoring explanation.
    summary: str = ""
    #: Uncertainty type this action addresses, e.g. ``wps_state``.
    uncertainty_type: Optional[str] = None
    #: Selector score, retained so scoring regressions are auditable.
    score: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "information_gaps": list(self.information_gaps),
            "supporting_evidence": list(self.supporting_evidence),
            "summary": self.summary,
            "uncertainty_type": self.uncertainty_type,
            "score": self.score,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "ActionReason":
        data = data or {}
        return cls(
            information_gaps=list(data.get("information_gaps") or []),
            supporting_evidence=list(data.get("supporting_evidence") or []),
            summary=str(data.get("summary") or ""),
            uncertainty_type=data.get("uncertainty_type"),
            score=data.get("score"),
        )


@dataclass(kw_only=True)
class ActionRequest(BaseContract):
    """A request to exercise one capability against one target."""

    SCHEMA = "action-request"
    VERSION = "1.0"
    PRODUCER = EngineId.DECISION.value
    REQUIRED_PAYLOAD_FIELDS = ("action_id", "capability", "objective")

    action_id: str
    #: Capability being requested, e.g. ``wireless_observation`` or a registered capability
    #: name when the Decision Engine selected a concrete implementation.
    capability: str
    objective: str = ActionObjective.RESOLVE_INFORMATION_GAP
    target: EntityRef = field(default_factory=lambda: EntityRef(type=TargetType.NONE.value))
    parameters: Dict[str, Any] = field(default_factory=dict)
    prerequisites: List[str] = field(default_factory=list)
    #: Outputs that must be produced for this action to count as useful.
    expected_outputs: List[str] = field(default_factory=list)
    verification_required: bool = False
    reason: ActionReason = field(default_factory=ActionReason)

    # --- optional extensions (MINOR-compatible additions, all defaulted) -------
    #: Concrete registered capability chosen to implement ``capability``.
    implementation: Optional[str] = None
    interface: Optional[str] = None
    timeout_seconds: Optional[int] = None
    origin: str = ActionOrigin.PLANNER
    #: Set when this request answers a VerificationActionRequest.
    verification_id: Optional[str] = None
    #: True once the Execution Engine has filled ``parameters`` from assessment state.
    prepared: bool = False
    priority: int = 0

    @classmethod
    def _coerce_payload(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        coerced = dict(payload)
        if isinstance(coerced.get("target"), dict):
            coerced["target"] = EntityRef.from_dict(coerced["target"])
        if isinstance(coerced.get("reason"), dict):
            coerced["reason"] = ActionReason.from_dict(coerced["reason"])
        return coerced

    def extra_structural_issues(self, payload: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        issues.extend(require_enum(payload, "objective", ActionObjective.ALL))
        issues.extend(require_enum(payload, "origin", ActionOrigin.ALL))
        issues.extend(require_type(payload, "parameters", dict))
        issues.extend(require_type(payload, "prerequisites", list))
        issues.extend(require_type(payload, "expected_outputs", list))
        issues.extend(require_type(payload, "prepared", bool))
        timeout = payload.get("timeout_seconds")
        if timeout is not None:
            if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout <= 0:
                issues.append(
                    ValidationIssue(
                        level=ValidationLevel.STRUCTURAL.value,
                        code="out_of_range",
                        message=f"timeout_seconds must be a positive integer, got {timeout!r}",
                        field="timeout_seconds",
                    )
                )
        return issues

    # ------------------------------------------------------------------ helpers

    @classmethod
    def for_verification(
        cls,
        *,
        assessment_id: str,
        action_id: str,
        verification_id: str,
        capability: str,
        target: EntityRef,
        parameters: Optional[Dict[str, Any]] = None,
        expected_outputs: Optional[List[str]] = None,
        information_gaps: Optional[List[str]] = None,
        supporting_evidence: Optional[List[str]] = None,
        summary: str = "",
        implementation: Optional[str] = None,
        interface: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
        correlation_id: Optional[str] = None,
        source_engine: str = EngineId.DECISION.value,
    ) -> "ActionRequest":
        """
        Build the VerificationActionRequest form of this contract.

        The Verification Engine calls this to ask the Decision Engine for more evidence; it
        never executes a tool itself.
        """
        kwargs: Dict[str, Any] = {
            "assessment_id": assessment_id,
            "action_id": action_id,
            "capability": capability,
            "objective": ActionObjective.RESOLVE_VERIFICATION_REQUIREMENT,
            "target": target,
            "parameters": dict(parameters or {}),
            "expected_outputs": list(expected_outputs or []),
            "verification_required": True,
            "reason": ActionReason(
                information_gaps=list(information_gaps or []),
                supporting_evidence=list(supporting_evidence or []),
                summary=summary,
                uncertainty_type="verification",
            ),
            "implementation": implementation,
            "interface": interface,
            "timeout_seconds": timeout_seconds,
            "origin": ActionOrigin.VERIFICATION,
            "verification_id": verification_id,
            "source_engine": source_engine,
        }
        if correlation_id:
            kwargs["correlation_id"] = correlation_id
        return cls(**kwargs)

    def with_parameters(self, parameters: Dict[str, Any], *, interface: Optional[str] = None, implementation: Optional[str] = None) -> "ActionRequest":
        """
        Return a *new* prepared request with concrete parameters.

        Messages are immutable records (specification section 16); the Execution Engine calls
        this during ``prepare()`` rather than mutating the Decision Engine's request.
        """
        return self.with_resolution(
            parameters=to_jsonable(dict(parameters)), interface=interface, implementation=implementation, prepared=True
        )

    def with_resolution(
        self,
        *,
        parameters: Optional[Dict[str, Any]] = None,
        interface: Optional[str] = None,
        implementation: Optional[str] = None,
        prepared: Optional[bool] = None,
    ) -> "ActionRequest":
        """
        Return a copy with selected fields resolved, leaving everything else untouched.

        Resolution (choosing which registered tool implements the capability, and which
        interface it runs on) does not by itself make a request executable, so ``prepared``
        is only changed when the caller says so. Keeping that distinction explicit matters:
        a request marked prepared has had its parameters derived from assessment state and is
        validated as such by the policy layer.
        """
        message = self.to_message()
        payload = dict(message["payload"])
        if parameters is not None:
            payload["parameters"] = parameters
        if interface is not None:
            payload["interface"] = interface
        if implementation is not None:
            payload["implementation"] = implementation
        if prepared is not None:
            payload["prepared"] = bool(prepared)
        message["payload"] = payload
        return ActionRequest.parse(message, assume_schema=True)

    @property
    def target_id(self) -> Optional[str]:
        return self.target.id if self.target else None

    def cites_gap(self, gap_id: str) -> bool:
        return gap_id in self.reason.information_gaps


class ValidationStatus:
    """Outcome of the policy layer for one ActionRequest."""

    APPROVED = "approved"
    REJECTED = "rejected"
    #: Structurally acceptable but not executable right now (e.g. capability unavailable);
    #: the Decision Engine should replan rather than treat this as a hard refusal.
    DEFERRED = "deferred"

    ALL: List[str] = [APPROVED, REJECTED, DEFERRED]


@dataclass(frozen=True)
class ValidationCheckRecord:
    """One entry of the ``checks`` array required by specification section 11."""

    type: str
    status: str
    detail: Optional[str] = None
    issues: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "status": self.status,
            "detail": self.detail,
            "issues": list(self.issues),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ValidationCheckRecord":
        return cls(
            type=str(data.get("type")),
            status=str(data.get("status")),
            detail=data.get("detail"),
            issues=list(data.get("issues") or []),
        )


@dataclass(kw_only=True)
class ActionValidationResult(BaseContract):
    """
    The Policy layer's verdict on one ActionRequest.

    A rejected action always carries a structured reason: ``checks`` shows which stage failed
    and ``rejection`` gives a machine-readable code plus detail, so the Decision Engine can
    replan instead of guessing.
    """

    SCHEMA = "action-validation-result"
    VERSION = "1.0"
    PRODUCER = EngineId.POLICY.value
    REQUIRED_PAYLOAD_FIELDS = ("action_id", "status")

    action_id: str
    status: str = ValidationStatus.APPROVED
    checks: List[ValidationCheckRecord] = field(default_factory=list)
    #: Structured rejection/deferral reason; ``None`` when approved.
    rejection: Optional[Dict[str, Any]] = None
    #: Parameters the policy layer validated (echoed so the audit trail is self-contained).
    validated_parameters: Dict[str, Any] = field(default_factory=dict)
    #: Capability whose metadata drove the checks.
    implementation: Optional[str] = None
    interface: Optional[str] = None
    #: Confidence that the approved action is safe and in scope, in [0, 1].
    confidence: float = 1.0

    @classmethod
    def _coerce_payload(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        coerced = dict(payload)
        checks = coerced.get("checks")
        if isinstance(checks, list) and checks and isinstance(checks[0], dict):
            coerced["checks"] = [ValidationCheckRecord.from_dict(item) for item in checks]
        return coerced

    def extra_structural_issues(self, payload: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        issues.extend(require_enum(payload, "status", ValidationStatus.ALL))
        issues.extend(require_type(payload, "checks", list))
        issues.extend(require_confidence(payload, "confidence"))
        if payload.get("status") in (ValidationStatus.REJECTED, ValidationStatus.DEFERRED) and not payload.get("rejection"):
            issues.append(
                ValidationIssue(
                    level=ValidationLevel.STRUCTURAL.value,
                    code="missing_reason",
                    message="a rejected or deferred action must contain a structured reason",
                    field="rejection",
                )
            )
        return issues

    @property
    def approved(self) -> bool:
        return self.status == ValidationStatus.APPROVED

    def failed_check(self, check_type: str) -> Optional[ValidationCheckRecord]:
        for check in self.checks:
            if check.type == check_type and check.status != "passed":
                return check
        return None
