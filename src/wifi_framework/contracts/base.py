"""
Base class for all inter-engine contracts.

Responsibilities:

1. Attach the common envelope metadata (specification section 2) to every message.
2. Provide one generic, deterministic serialiser so individual contracts only declare
   their fields instead of hand-writing ``to_dict``/``from_dict`` pairs that drift apart.
3. Support both wire shapes the specification uses: the *enveloped* form
   (``{... metadata ..., "payload": {...}}``) and the *flat* form shown by the concrete
   examples (metadata and payload fields side by side). ``parse`` accepts either.
4. Forward compatibility: payload keys this consumer does not know are preserved in
   ``extensions`` and re-emitted on serialisation. A producer may therefore add optional
   fields as a MINOR version bump without older consumers rejecting the message, which is
   exactly what Semantic Versioning promises for backward-compatible additions.
5. Structural validation, so every engine can validate before processing.

All contracts are keyword-only dataclasses: positional construction of a message with eight
metadata fields and a variable payload is an invitation to transpose arguments silently.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, fields as dc_fields
from datetime import datetime
from typing import Any, ClassVar, Dict, List, Optional, Sequence, Tuple

from .common import to_jsonable
from .envelope import (
    ContractEnvelope,
    ContractVersion,
    EngineId,
    format_timestamp,
    new_correlation_id,
    new_message_id,
    parse_timestamp,
    utc_now,
)
from .errors import ContractValidationError
from .validation import (
    LEVEL_ORDER,
    ValidationCheck,
    ValidationIssue,
    ValidationLevel,
    ValidationResult,
    require_fields,
)

#: Fields that belong to the envelope rather than to the contract payload.
METADATA_FIELDS: Tuple[str, ...] = (
    "assessment_id",
    "source_engine",
    "correlation_id",
    "message_id",
    "timestamp",
    "extensions",
)


@dataclass(kw_only=True)
class BaseContract:
    """Common behaviour and metadata for every contract."""

    #: Contract name, e.g. ``"action-request"``. Subclasses must set this.
    SCHEMA: ClassVar[str] = ""
    #: ``MAJOR.MINOR`` version produced by this implementation.
    VERSION: ClassVar[str] = "1.0"
    #: Payload fields that must be present and non-empty for the message to be structural.
    REQUIRED_PAYLOAD_FIELDS: ClassVar[Sequence[str]] = ()
    #: Human-readable owner subsystem, per the specification's contract-ownership table.
    PRODUCER: ClassVar[str] = EngineId.ORCHESTRATOR.value

    assessment_id: str
    #: Defaults to this contract's declared producer when not supplied explicitly.
    source_engine: str = ""
    correlation_id: str = field(default_factory=new_correlation_id)
    message_id: str = field(default_factory=new_message_id)
    timestamp: datetime = field(default_factory=utc_now)
    #: Unknown payload keys received from a newer producer (forward compatibility).
    extensions: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.SCHEMA:
            raise ContractValidationError(f"{type(self).__name__} must declare SCHEMA")
        ContractVersion.parse(self.VERSION)
        if not self.assessment_id or not str(self.assessment_id).strip():
            raise ContractValidationError(
                "assessment_id is required; engines must not infer assessment identity "
                "from filenames, process state or global variables"
            )
        if isinstance(self.timestamp, str):
            self.timestamp = parse_timestamp(self.timestamp)
        if not isinstance(self.timestamp, datetime):
            raise ContractValidationError(
                f"timestamp must be a datetime, got {type(self.timestamp).__name__}"
            )
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=utc_now().tzinfo)
        if not isinstance(self.source_engine, str):
            self.source_engine = str(getattr(self.source_engine, "value", self.source_engine))
        if not self.source_engine.strip():
            # A message always names its producer; default to the contract's declared owner
            # rather than leaving the field blank for a consumer to guess at.
            self.source_engine = self.PRODUCER
        self._normalise_typed_fields()

    def _normalise_typed_fields(self) -> None:
        """
        Coerce nested payload fields to their declared types on construction.

        ``parse()`` already coerces, so without this a contract built in-process would carry
        plain dicts where a parsed one carries typed objects, and every consumer would have to
        defend against both shapes. The coercion hooks are idempotent, so typed values pass
        through untouched. ``object.__setattr__`` is used because contracts may be frozen.
        """
        raw = {
            field.name: getattr(self, field.name)
            for field in dc_fields(self)
            if field.name not in METADATA_FIELDS
        }
        for name, value in self._coerce_payload(raw).items():
            if name in raw and value is not raw[name]:
                object.__setattr__(self, name, value)

    # ---------------------------------------------------------------- envelope

    def envelope(self) -> ContractEnvelope:
        """Return the common metadata envelope for this message."""
        return ContractEnvelope(
            schema=self.SCHEMA,
            version=self.VERSION,
            message_id=self.message_id,
            assessment_id=self.assessment_id,
            timestamp=format_timestamp(self.timestamp),
            source_engine=self.source_engine,
            correlation_id=self.correlation_id,
        )

    def with_correlation(self, correlation_id: str) -> "BaseContract":
        """
        Return a copy of this message bound to a different correlation id.

        Used to tie a verification-driven action back to the operation that requested it
        without mutating the original immutable record.
        """
        message = self.to_message()
        message["correlation_id"] = correlation_id
        return type(self).parse(message, assume_schema=True)

    # ------------------------------------------------------------- serialising

    def payload(self) -> Dict[str, Any]:
        """Contract-specific data, excluding envelope metadata."""
        known = {
            f.name: to_jsonable(getattr(self, f.name))
            for f in dc_fields(self)
            if f.name not in METADATA_FIELDS
        }
        if self.extensions:
            known.update(to_jsonable(self.extensions))
        return known

    def to_message(self) -> Dict[str, Any]:
        """Canonical wire form: envelope metadata plus a nested ``payload`` object."""
        message = self.envelope().to_dict()
        message["payload"] = self.payload()
        return message

    def to_dict(self) -> Dict[str, Any]:
        """Flat form, as used by the specification's concrete contract examples."""
        flat = self.envelope().to_dict()
        flat.update(self.payload())
        return flat

    def _flat_form(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        flat = self.envelope().to_dict()
        flat.update(payload)
        return flat

    def digest(self) -> str:
        """
        Deterministic SHA-256 of the serialised message.

        Used for the experience record's ``state_before`` / ``state_after`` fields, so a
        state transition is identifiable without embedding the whole state in the record.
        """
        # to_jsonable has already normalised every value, including its deterministic
        # last resort, so no `default=` hook is needed here. Passing `default=str`
        # would reintroduce address-bearing reprs and make the digest vary between
        # processes, contradicting the determinism this method promises.
        encoded = json.dumps(to_jsonable(self.to_message()), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------ parsing

    @classmethod
    def parse(cls, data: Dict[str, Any], *, registry: Any = None, assume_schema: bool = False) -> "BaseContract":
        """
        Build a contract instance from either wire form, validating as it goes.

        ``registry`` is an optional :class:`~wifi_framework.contracts.registry.ContractRegistry`
        used to reject unsupported major versions. When omitted, the default registry is
        used, so a consumer cannot accidentally skip version negotiation.
        """
        if not isinstance(data, dict):
            raise ContractValidationError(f"{cls.SCHEMA}: message must be a JSON object", schema=cls.SCHEMA)

        if registry is None:
            from .registry import get_contract_registry

            registry = get_contract_registry()

        envelope_data, payload = _split_message(data)
        envelope = ContractEnvelope.from_dict(envelope_data)

        if not assume_schema and envelope.schema != cls.SCHEMA:
            raise ContractValidationError(
                f"schema mismatch: message declares '{envelope.schema}' but '{cls.SCHEMA}' was expected",
                schema=envelope.schema,
                version=envelope.version,
            )
        # Reject unsupported major versions rather than guessing at incompatible data.
        registry.assert_supported(envelope.schema, envelope.version)
        if ContractVersion.parse(envelope.version).major != ContractVersion.parse(cls.VERSION).major:
            raise ContractValidationError(
                f"consumer for '{cls.SCHEMA}' implements major {ContractVersion.parse(cls.VERSION).major}, "
                f"message declares {envelope.version}",
                schema=envelope.schema,
                version=envelope.version,
            )

        instance = cls._build(payload, envelope)
        issues = instance.structural_issues()
        if issues:
            raise ContractValidationError(
                f"{cls.SCHEMA} failed structural validation: " + "; ".join(i.message for i in issues),
                issues=[i.message for i in issues],
                schema=envelope.schema,
                version=envelope.version,
            )
        return instance

    @classmethod
    def _build(cls, payload: Dict[str, Any], envelope: ContractEnvelope) -> "BaseContract":
        coerced = cls._coerce_payload(dict(payload))
        known = {f.name for f in dc_fields(cls)}
        kwargs: Dict[str, Any] = {
            name: value for name, value in coerced.items() if name in known and name not in METADATA_FIELDS
        }
        # Payload keys this consumer's class does not declare are preserved as extensions so
        # that a newer producer's compatible additions survive a round-trip.
        extensions = {name: value for name, value in coerced.items() if name not in known}
        for name in METADATA_FIELDS:
            extensions.pop(name, None)
        kwargs["extensions"] = extensions
        kwargs["assessment_id"] = envelope.assessment_id
        kwargs["source_engine"] = envelope.source_engine
        kwargs["correlation_id"] = envelope.correlation_id
        kwargs["message_id"] = envelope.message_id
        kwargs["timestamp"] = parse_timestamp(envelope.timestamp)
        return cls(**kwargs)  # type: ignore[call-arg]

    @classmethod
    def _coerce_payload(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Hook for converting nested payload objects into typed value objects.

        The default implementation returns the payload unchanged; contracts with typed
        nested fields (for example ``target`` or ``failure``) override it.
        """
        return payload

    # --------------------------------------------------------------- validation

    def structural_issues(self) -> List[ValidationIssue]:
        """Structural problems with this message (level 1 of 3)."""
        issues: List[ValidationIssue] = []
        if not self.message_id or not str(self.message_id).strip():
            issues.append(ValidationIssue(level=ValidationLevel.STRUCTURAL.value, code="empty_field", message="message_id is required", field="message_id"))
        if not self.correlation_id or not str(self.correlation_id).strip():
            issues.append(ValidationIssue(level=ValidationLevel.STRUCTURAL.value, code="empty_field", message="correlation_id is required", field="correlation_id"))
        try:
            format_timestamp(self.timestamp)
        except ContractValidationError as exc:
            issues.append(ValidationIssue(level=ValidationLevel.STRUCTURAL.value, code="invalid_timestamp", message=str(exc), field="timestamp"))
        try:
            EngineId(self.source_engine)
        except ValueError:
            issues.append(
                ValidationIssue(
                    level=ValidationLevel.STRUCTURAL.value,
                    code="invalid_enum_value",
                    message=f"source_engine '{self.source_engine}' is not a known engine",
                    field="source_engine",
                )
            )
        payload = self.payload()
        issues.extend(require_fields(payload, list(self.REQUIRED_PAYLOAD_FIELDS)))
        issues.extend(self.extra_structural_issues(payload))
        return issues

    def extra_structural_issues(self, payload: Dict[str, Any]) -> List[ValidationIssue]:
        """Hook for contract-specific structural rules beyond required-field presence."""
        return []

    def validate(self, levels: Optional[Sequence[ValidationLevel]] = None) -> ValidationResult:
        """
        Validate this message through the requested levels.

        Only structural validation is meaningful without a consumer context; semantic and
        operational validation require the assessment state and the capability registry and
        are performed by :mod:`wifi_framework.core.policy`.
        """
        requested = list(levels or [ValidationLevel.STRUCTURAL])
        checks: List[ValidationCheck] = []
        issues: List[ValidationIssue] = []
        reached = ValidationLevel.STRUCTURAL.value

        for level in LEVEL_ORDER:
            if level not in requested:
                checks.append(ValidationCheck.skipped(level.value, "not requested"))
                continue
            reached = level.value
            if level == ValidationLevel.STRUCTURAL:
                level_issues = self.structural_issues()
            else:
                level_issues = self.contextual_issues(level)
            if level_issues:
                issues.extend(level_issues)
                checks.append(
                    ValidationCheck.failed(
                        level.value,
                        f"{len(level_issues)} problem(s): " + "; ".join(i.message for i in level_issues),
                        level_issues,
                    )
                )
                # Short-circuit: a message that is not structural cannot be judged semantically.
                break
            checks.append(ValidationCheck.passed(level.value))

        return ValidationResult(ok=not issues, level_reached=reached, checks=checks, issues=issues)

    def contextual_issues(self, level: ValidationLevel) -> List[ValidationIssue]:
        """Hook for semantic/operational checks a contract can perform on itself."""
        return []


def _split_message(data: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Split an incoming message into envelope metadata and payload.

    Accepts the enveloped form (``payload`` key present) and the flat form, so producers and
    consumers may use whichever shape the specification shows for that contract.
    """
    envelope_keys = ("schema", "version", "message_id", "assessment_id", "timestamp", "source_engine", "correlation_id")
    envelope_data = {key: data[key] for key in envelope_keys if key in data}
    if "payload" in data and isinstance(data["payload"], dict):
        payload = dict(data["payload"])
    else:
        payload = {key: value for key, value in data.items() if key not in envelope_keys}
    return envelope_data, payload


def message_digest(message: Any) -> str:
    """SHA-256 digest of any contract or JSON-serialisable mapping."""
    if isinstance(message, BaseContract):
        return message.digest()
    encoded = json.dumps(to_jsonable(message), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
