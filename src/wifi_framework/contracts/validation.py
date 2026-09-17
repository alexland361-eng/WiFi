"""
Three-level contract validation.

The specification requires every engine to validate incoming contracts before processing
them, at three distinct levels:

* **structural**  - is the schema valid, are required fields present, are types correct?
* **semantic**    - do referenced entities exist, is the action compatible with the
                    capability, are parameters internally consistent?
* **operational** - is the interface available, is the capability supported, is the action
                    permitted by the assessment scope?

A structurally valid message is therefore not automatically an executable action: the levels
are ordered and short-circuit, and the result records which level rejected the message.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ValidationLevel(str, Enum):
    STRUCTURAL = "structural"
    SEMANTIC = "semantic"
    OPERATIONAL = "operational"


#: Canonical ordering; a failing level stops further validation.
LEVEL_ORDER: List[ValidationLevel] = [
    ValidationLevel.STRUCTURAL,
    ValidationLevel.SEMANTIC,
    ValidationLevel.OPERATIONAL,
]


class CheckStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class ValidationIssue:
    """A single validation failure or note."""

    level: str
    code: str
    message: str
    field: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level,
            "code": self.code,
            "message": self.message,
            "field": self.field,
            "details": self.details,
        }


@dataclass(frozen=True)
class ValidationCheck:
    """
    One named check and its outcome.

    This is the unit used by ``action-validation-result``'s ``checks`` array, so a rejected
    action always carries a structured reason rather than a free-text error string.
    """

    type: str
    status: str
    detail: Optional[str] = None
    issues: List[ValidationIssue] = field(default_factory=list)

    @classmethod
    def passed(cls, check_type: str, detail: Optional[str] = None) -> "ValidationCheck":
        return cls(type=check_type, status=CheckStatus.PASSED.value, detail=detail)

    @classmethod
    def failed(
        cls, check_type: str, detail: str, issues: Optional[List[ValidationIssue]] = None
    ) -> "ValidationCheck":
        return cls(
            type=check_type,
            status=CheckStatus.FAILED.value,
            detail=detail,
            issues=list(issues or []),
        )

    @classmethod
    def skipped(cls, check_type: str, detail: Optional[str] = None) -> "ValidationCheck":
        return cls(type=check_type, status=CheckStatus.SKIPPED.value, detail=detail)

    @property
    def ok(self) -> bool:
        return self.status == CheckStatus.PASSED.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "status": self.status,
            "detail": self.detail,
            "issues": [issue.to_dict() for issue in self.issues],
        }


@dataclass
class ValidationResult:
    """Aggregate outcome of validating one message."""

    ok: bool
    level_reached: str
    checks: List[ValidationCheck] = field(default_factory=list)
    issues: List[ValidationIssue] = field(default_factory=list)

    @property
    def error_messages(self) -> List[str]:
        return [issue.message for issue in self.issues]

    def first_failure(self) -> Optional[ValidationCheck]:
        for check in self.checks:
            if check.status == CheckStatus.FAILED.value:
                return check
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "level_reached": self.level_reached,
            "checks": [check.to_dict() for check in self.checks],
            "issues": [issue.to_dict() for issue in self.issues],
        }


def require_fields(
    payload: Dict[str, Any], required: List[str], level: str = ValidationLevel.STRUCTURAL.value
) -> List[ValidationIssue]:
    """Return issues for every required field that is missing or empty."""
    issues: List[ValidationIssue] = []
    for name in required:
        if name not in payload:
            issues.append(ValidationIssue(level=level, code="missing_field", message=f"missing required field '{name}'", field=name))
            continue
        value = payload[name]
        # ``0`` and ``False`` are legitimate values; only None/"" are treated as absent.
        if value is None or (isinstance(value, str) and not value.strip()):
            issues.append(ValidationIssue(level=level, code="empty_field", message=f"required field '{name}' is empty", field=name))
    return issues


def require_type(
    payload: Dict[str, Any], name: str, expected: type, level: str = ValidationLevel.STRUCTURAL.value
) -> List[ValidationIssue]:
    """Return an issue when ``payload[name]`` is present but of the wrong type."""
    if name not in payload or payload[name] is None:
        return []
    if not isinstance(payload[name], expected):
        return [
            ValidationIssue(
                level=level,
                code="wrong_type",
                message=f"field '{name}' must be {expected.__name__}, got {type(payload[name]).__name__}",
                field=name,
            )
        ]
    return []


def require_enum(
    payload: Dict[str, Any], name: str, allowed: List[str], level: str = ValidationLevel.STRUCTURAL.value
) -> List[ValidationIssue]:
    """Return an issue when ``payload[name]`` is outside the enumerated value set."""
    value = payload.get(name)
    if value is None:
        return []
    if value not in allowed:
        return [
            ValidationIssue(
                level=level,
                code="invalid_enum_value",
                message=f"field '{name}' = {value!r} is not one of {allowed}",
                field=name,
                details={"allowed": list(allowed)},
            )
        ]
    return []


def require_confidence(
    payload: Dict[str, Any], name: str = "confidence", level: str = ValidationLevel.STRUCTURAL.value
) -> List[ValidationIssue]:
    """Confidence is a closed interval; out-of-range values are a producer bug."""
    value = payload.get(name)
    if value is None:
        return []
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return [ValidationIssue(level=level, code="wrong_type", message=f"'{name}' must be a number", field=name)]
    if not 0.0 <= float(value) <= 1.0:
        return [
            ValidationIssue(
                level=level,
                code="out_of_range",
                message=f"'{name}' must be within [0.0, 1.0], got {value}",
                field=name,
            )
        ]
    return []
