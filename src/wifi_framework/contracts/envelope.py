"""
Common contract envelope, engine identity and version handling.

Design precedent: the envelope follows the CloudEvents 1.0 discipline of a small set of
required context attributes plus a data payload.  Mapping:

    CloudEvents 1.0        this framework
    -------------------    ------------------
    type (required)        schema
    specversion (required) version
    id (required)          message_id
    source (required)      source_engine
    time (RFC 3339)        timestamp (ISO-8601, timezone aware, required here)
    data                   payload
    extension attributes   correlation_id, assessment_id

Versioning follows Semantic Versioning 2.0.0 semantics for the two components used here:
MAJOR is incremented for breaking changes, MINOR for backward-compatible additions.
A consumer rejects an unknown MAJOR.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Tuple

from .errors import ContractValidationError

#: Envelope schema/version of the framing itself (not of the payload contract).
ENVELOPE_SCHEMA = "contract-envelope"
ENVELOPE_VERSION = "1.0"

_VERSION_RE = re.compile(r"^(\d+)\.(\d+)$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class EngineId(str, Enum):
    """
    Identifier of a subsystem that may produce or consume contracts.

    The specification's contract-ownership table names these producers explicitly; the
    enum exists so that a message can never carry a free-text, misspelled producer.
    """

    WORLD_MODEL = "world_model"
    DECISION = "decision"
    EXECUTION = "execution"
    EVIDENCE = "evidence"
    VERIFICATION = "verification"
    POLICY = "policy"
    EXPERIENCE = "experience"
    AI = "ai"
    #: The orchestrator (AssessmentEngine). It routes messages but owns none of them.
    ORCHESTRATOR = "orchestrator"
    #: Operator-supplied input (CLI / configuration).
    OPERATOR = "operator"


def new_message_id() -> str:
    """Return a fresh RFC 4122 UUID4 string for ``message_id``."""
    return str(uuid.uuid4())


def new_correlation_id() -> str:
    """Return a fresh RFC 4122 UUID4 string for ``correlation_id``."""
    return str(uuid.uuid4())


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def format_timestamp(value: datetime) -> str:
    """
    Serialise a datetime as ISO-8601 with an explicit UTC offset.

    Naive datetimes are rejected: an assessment record without a timezone cannot be
    ordered against records produced elsewhere, which would silently corrupt the
    staleness reasoning used by the Verification Engine.
    """
    if not isinstance(value, datetime):
        raise ContractValidationError(f"timestamp must be a datetime, got {type(value).__name__}")
    if value.tzinfo is None:
        raise ContractValidationError("timestamp must be timezone aware (naive datetime rejected)")
    return value.astimezone(timezone.utc).isoformat()


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp, normalising a trailing ``Z`` to ``+00:00``."""
    if not isinstance(value, str) or not value:
        raise ContractValidationError(f"timestamp must be a non-empty string, got {value!r}")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ContractValidationError(f"timestamp is not valid ISO-8601: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ContractValidationError(f"timestamp must carry a UTC offset: {value!r}")
    return parsed


@dataclass(frozen=True)
class ContractVersion:
    """A parsed ``MAJOR.MINOR`` contract version."""

    major: int
    minor: int

    @classmethod
    def parse(cls, text: str) -> "ContractVersion":
        if not isinstance(text, str):
            raise ContractValidationError(f"version must be a string, got {type(text).__name__}")
        match = _VERSION_RE.match(text.strip())
        if not match:
            raise ContractValidationError(
                f"version must look like 'MAJOR.MINOR' (e.g. '1.0'), got {text!r}"
            )
        return cls(major=int(match.group(1)), minor=int(match.group(2)))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}"

    def is_breaking_against(self, other: "ContractVersion") -> bool:
        """True when moving from ``other`` to ``self`` requires consumer changes."""
        return self.major != other.major

    def is_compatible_addition_to(self, other: "ContractVersion") -> bool:
        """True when ``self`` only adds capability relative to ``other``."""
        return self.major == other.major and self.minor >= other.minor

    def as_tuple(self) -> Tuple[int, int]:
        return (self.major, self.minor)


@dataclass(frozen=True)
class ContractEnvelope:
    """
    The metadata shared by every inter-engine message.

    All eight fields of the specification's "Common Contract Metadata" section are
    required; there is no optional-metadata mode, because a message that cannot be
    attributed to an assessment and a producer cannot be audited.
    """

    schema: str
    version: str
    message_id: str
    assessment_id: str
    timestamp: str
    source_engine: str
    correlation_id: str

    @property
    def parsed_version(self) -> ContractVersion:
        return ContractVersion.parse(self.version)

    @property
    def parsed_timestamp(self) -> datetime:
        return parse_timestamp(self.timestamp)

    def to_dict(self) -> dict:
        return {
            "schema": self.schema,
            "version": self.version,
            "message_id": self.message_id,
            "assessment_id": self.assessment_id,
            "timestamp": self.timestamp,
            "source_engine": self.source_engine,
            "correlation_id": self.correlation_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ContractEnvelope":
        if not isinstance(data, dict):
            raise ContractValidationError("envelope must be a JSON object")
        required = (
            "schema",
            "version",
            "message_id",
            "assessment_id",
            "timestamp",
            "source_engine",
            "correlation_id",
        )
        missing = [field for field in required if not data.get(field)]
        if missing:
            raise ContractValidationError(
                f"envelope is missing required metadata: {', '.join(missing)}"
            )
        # Validate the two fields whose shape carries semantic weight.
        ContractVersion.parse(str(data["version"]))
        parse_timestamp(str(data["timestamp"]))
        return cls(
            schema=str(data["schema"]),
            version=str(data["version"]),
            message_id=str(data["message_id"]),
            assessment_id=str(data["assessment_id"]),
            timestamp=str(data["timestamp"]),
            source_engine=str(data["source_engine"]),
            correlation_id=str(data["correlation_id"]),
        )


def looks_like_uuid(value: Optional[str]) -> bool:
    """True when ``value`` is a canonical UUID string (used by semantic validation)."""
    return bool(value) and bool(_UUID_RE.match(str(value)))
