"""
``execution-result`` contract (version 1.0).

Producer: Execution Engine. Consumers: Evidence Engine and Decision Engine.

Two rules from the specification shape this module:

1. "A failed execution must remain a failed execution. The Execution Engine must never
   convert a tool failure into an apparently successful result." The status is therefore an
   enumerated state machine, not a boolean, and ``failure`` is mandatory whenever the status
   is not ``success``.
2. Raw output is referenced, not inlined: ``stdout_artifact`` / ``stderr_artifact`` /
   ``artifacts`` point at the artifact store, so nothing is truncated away before the
   Evidence Engine has read it.

The command is recorded as an argument list. This framework never builds a shell string, so
the recorded command is exactly what was passed to ``subprocess.run`` and can be re-run by an
auditor without reinterpretation.

Note on naming: ``wifi_framework.core.execution.executor.ExecutionResult`` is the pre-existing
internal result object of the adapter layer (v0.1.0). This contract is the inter-engine
message. Consumers should import one of them under an alias to keep the distinction visible.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .base import BaseContract
from .common import ArtifactRef, InterfaceRef, ToolRef, to_jsonable
from .envelope import EngineId
from .validation import (
    ValidationIssue,
    ValidationLevel,
    require_enum,
    require_type,
)


class ExecutionStatus:
    """
    Execution states from specification section 5.

    ``unsupported`` and ``rejected`` are terminal pre-execution states: they mean the
    capability could not or must not be attempted, which the framework must report explicitly
    rather than representing as an empty successful result.
    """

    ACCEPTED = "accepted"
    RUNNING = "running"
    SUCCESS = "success"
    #: Ran, produced output, but part of the requested work did not complete.
    PARTIAL = "partial"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    #: Environment cannot satisfy the capability (hardware, driver, privileges, tool version).
    UNSUPPORTED = "unsupported"
    #: Policy layer refused the action.
    REJECTED = "rejected"

    ALL: List[str] = [
        ACCEPTED,
        RUNNING,
        SUCCESS,
        PARTIAL,
        FAILED,
        TIMEOUT,
        CANCELLED,
        UNSUPPORTED,
        REJECTED,
    ]

    #: Statuses that mean the tool actually ran.
    TERMINAL_EXECUTED: List[str] = [SUCCESS, PARTIAL, FAILED, TIMEOUT, CANCELLED]
    #: Statuses that mean it never ran.
    TERMINAL_NOT_EXECUTED: List[str] = [UNSUPPORTED, REJECTED]
    #: Anything that is not a clean success.
    NON_SUCCESS: List[str] = [PARTIAL, FAILED, TIMEOUT, CANCELLED, UNSUPPORTED, REJECTED]


class FailureCategory:
    """Why an execution did not succeed, in terms the Decision Engine can replan against."""

    TOOL_NOT_FOUND = "tool_not_found"
    TOOL_VERSION = "tool_version_incompatible"
    INTERFACE_UNAVAILABLE = "interface_unavailable"
    UNSUPPORTED_DRIVER = "unsupported_driver"
    INSUFFICIENT_PRIVILEGES = "insufficient_privileges"
    RADIO_BLOCKED = "radio_blocked"
    INVALID_PARAMETERS = "invalid_parameters"
    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"
    SCOPE_DENIED = "scope_denied"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    PARSER_ERROR = "parser_error"
    TOOL_ERROR = "tool_error"
    INTERNAL_ERROR = "internal_error"
    CANCELLED = "cancelled"

    ALL: List[str] = [
        TOOL_NOT_FOUND,
        TOOL_VERSION,
        INTERFACE_UNAVAILABLE,
        UNSUPPORTED_DRIVER,
        INSUFFICIENT_PRIVILEGES,
        RADIO_BLOCKED,
        INVALID_PARAMETERS,
        TIMEOUT,
        PERMISSION_DENIED,
        SCOPE_DENIED,
        CAPABILITY_UNAVAILABLE,
        PARSER_ERROR,
        TOOL_ERROR,
        INTERNAL_ERROR,
        CANCELLED,
    ]

    #: Failures that another attempt could plausibly fix (drives replanning).
    RETRIABLE: List[str] = [TIMEOUT, TOOL_ERROR, INTERFACE_UNAVAILABLE, RADIO_BLOCKED, INTERNAL_ERROR]


@dataclass(frozen=True)
class ExecutionFailure:
    """Structured failure representation; ``None`` only for a clean success."""

    code: str
    category: str
    message: str
    retriable: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "category": self.category,
            "message": self.message,
            "retriable": self.retriable,
            "details": to_jsonable(self.details),
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> Optional["ExecutionFailure"]:
        if not data:
            return None
        return cls(
            code=str(data.get("code") or FailureCategory.INTERNAL_ERROR),
            category=str(data.get("category") or FailureCategory.INTERNAL_ERROR),
            message=str(data.get("message") or ""),
            retriable=bool(data.get("retriable", False)),
            details=dict(data.get("details") or {}),
        )


@dataclass(kw_only=True)
class ExecutionResult(BaseContract):
    """The Execution Engine's report about one attempted capability."""

    SCHEMA = "execution-result"
    VERSION = "1.0"
    PRODUCER = EngineId.EXECUTION.value
    REQUIRED_PAYLOAD_FIELDS = ("action_id", "execution_id", "status", "capability")

    action_id: str
    execution_id: str
    status: str
    capability: str

    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_ms: int = 0
    exit_code: Optional[int] = None

    #: Artifact identifiers for the tool's raw streams.
    stdout_artifact: Optional[str] = None
    stderr_artifact: Optional[str] = None
    artifacts: List[ArtifactRef] = field(default_factory=list)

    tool: Optional[ToolRef] = None
    interface: Optional[InterfaceRef] = None
    failure: Optional[ExecutionFailure] = None

    #: Extraction problems the parser could not express as evidence: a document that
    #: did not parse, an output format it did not recognise. The run is not a failure -
    #: the tool executed and exited cleanly - so ``status`` and ``failure`` say nothing
    #: about it. Kept separate from ``warnings`` because the Evidence Engine folds these
    #: into ``EvidenceSet.parse_issues``, and mixing general advisories in would make
    #: every warning claim to be an extraction problem.
    parse_warnings: List[str] = field(default_factory=list)
    #: Concrete invocation, as an argument list (never a shell string).
    command: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    #: Implementation actually used, when it differs from the requested capability.
    implementation: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    #: Correlation to the assessment scope that authorised this action.
    scope_authorised: bool = False

    @classmethod
    def _coerce_payload(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        coerced = dict(payload)
        if isinstance(coerced.get("tool"), dict):
            coerced["tool"] = ToolRef.from_dict(coerced["tool"])
        if isinstance(coerced.get("interface"), dict):
            coerced["interface"] = InterfaceRef.from_dict(coerced["interface"])
        if isinstance(coerced.get("failure"), dict):
            coerced["failure"] = ExecutionFailure.from_dict(coerced["failure"])
        artifacts = coerced.get("artifacts")
        if isinstance(artifacts, list) and artifacts and isinstance(artifacts[0], dict):
            coerced["artifacts"] = [ArtifactRef.from_dict(item) for item in artifacts]
        return coerced

    def extra_structural_issues(self, payload: Dict[str, Any]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        issues.extend(require_enum(payload, "status", ExecutionStatus.ALL))
        issues.extend(require_type(payload, "duration_ms", int))
        issues.extend(require_type(payload, "artifacts", list))
        issues.extend(require_type(payload, "command", list))
        if payload.get("failure"):
            failure = payload["failure"]
            category = failure.category if isinstance(failure, ExecutionFailure) else failure.get("category")
            if category and category not in FailureCategory.ALL:
                issues.append(
                    ValidationIssue(
                        level=ValidationLevel.STRUCTURAL.value,
                        code="invalid_enum_value",
                        message=f"failure.category '{category}' is not a known category",
                        field="failure.category",
                        details={"allowed": FailureCategory.ALL},
                    )
                )
        return issues

    def contextual_issues(self, level) -> List[ValidationIssue]:
        """
        Semantic rule: a non-success status must explain itself, and a success must not.

        This is the enforcement point for "a failed execution must remain a failed
        execution": an ExecutionResult claiming success while carrying a failure, or claiming
        failure while carrying none, is rejected before the Evidence Engine sees it.
        """
        issues: List[ValidationIssue] = []
        from .validation import ValidationLevel

        if level != ValidationLevel.SEMANTIC:
            # Only the semantic level can judge status/failure consistency; the operational
            # level needs environment context and is performed by the policy layer.
            return issues
        status = self.status
        if status == ExecutionStatus.SUCCESS and self.failure is not None:
            issues.append(
                ValidationIssue(
                    level="semantic",
                    code="success_with_failure",
                    message="status 'success' must not carry a failure record",
                    field="failure",
                )
            )
        if status in ExecutionStatus.NON_SUCCESS and status != ExecutionStatus.PARTIAL and self.failure is None:
            issues.append(
                ValidationIssue(
                    level="semantic",
                    code="failure_without_reason",
                    message=f"status '{status}' must carry a structured failure record",
                    field="failure",
                )
            )
        if status in ExecutionStatus.TERMINAL_NOT_EXECUTED and self.exit_code is not None:
            issues.append(
                ValidationIssue(
                    level="semantic",
                    code="exit_code_without_execution",
                    message=f"status '{status}' means the tool never ran, so exit_code must be null",
                    field="exit_code",
                )
            )
        if status in ExecutionStatus.TERMINAL_EXECUTED and self.exit_code is None:
            issues.append(
                ValidationIssue(
                    level="semantic",
                    code="missing_exit_code",
                    message=f"status '{status}' requires an exit_code",
                    field="exit_code",
                )
            )
        if self.duration_ms < 0:
            issues.append(
                ValidationIssue(
                    level="semantic",
                    code="negative_duration",
                    message=f"duration_ms must be >= 0, got {self.duration_ms}",
                    field="duration_ms",
                )
            )
        return issues

    # ------------------------------------------------------------------ helpers

    @property
    def succeeded(self) -> bool:
        return self.status == ExecutionStatus.SUCCESS

    @property
    def executed(self) -> bool:
        """True when the real tool was invoked, whatever the outcome."""
        return self.status in ExecutionStatus.TERMINAL_EXECUTED

    def artifact(self, artifact_id: str) -> Optional[ArtifactRef]:
        for item in self.artifacts:
            if item.id == artifact_id:
                return item
        return None

    def artifacts_of_kind(self, kind: str) -> List[ArtifactRef]:
        return [item for item in self.artifacts if item.kind == kind]
