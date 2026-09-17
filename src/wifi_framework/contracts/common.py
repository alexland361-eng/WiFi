"""
Shared, reusable value objects referenced by more than one contract.

These are deliberately small: they exist so that provenance, entity references and artifact
references mean the same thing in `execution-result`, `evidence-set` and
`verification-result` instead of being re-invented per contract.

Provenance follows the W3C PROV data model shape: an observation (Entity) records the
execution that generated it (``wasGeneratedBy`` -> ``execution_id``), the action that caused
that execution, and the artifacts it was derived from (``wasDerivedFrom`` -> ``derived_from``).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


#: Matches CPython's default object repr, which embeds a memory address.
_DEFAULT_REPR = re.compile(r"^<.* object at 0x[0-9a-fA-F]+>$")


def to_jsonable(value: Any) -> Any:
    """
    Convert any value used inside a contract payload into JSON-serialisable form.

    Handles, in order: ``None``/primitives, enums, datetimes, objects exposing ``to_dict``,
    sets/frozensets (sorted for deterministic output), lists/tuples, dicts, and finally
    ``dataclasses.asdict``-style recursion for plain dataclasses.

    Deterministic output matters: contract messages are hashed for the experience record's
    ``state_before``/``state_after`` fields, so serialisation must not depend on set ordering.
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        from .envelope import format_timestamp

        return format_timestamp(value)
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return to_jsonable(value.to_dict())
    if isinstance(value, (set, frozenset)):
        return [to_jsonable(item) for item in sorted(value, key=lambda item: str(item))]
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if hasattr(value, "__dataclass_fields__"):
        from dataclasses import fields as dc_fields

        return {f.name: to_jsonable(getattr(value, f.name)) for f in dc_fields(value)}
    # Last resort: keep the message serialisable rather than raising mid-assessment.
    text = str(value)
    # A default object repr embeds a memory address - `<Foo object at 0x7f8a2c>` -
    # so using it verbatim makes the value differ between processes, and with it
    # every digest built from it. `digest()` is documented as deterministic and is
    # used for the experience record's state_before/state_after, so a digest that
    # changes between runs would report a state transition that never happened.
    # Within one process CPython reuses freed addresses, which hides this: two
    # instances digest identically in-process and differently across processes.
    # Substituting the type name keeps serialisation total and deterministic. It
    # does conflate two distinct instances of an unserialisable type, which is
    # acceptable because contract fields are typed dataclasses and primitives; an
    # opaque object reaching here is already a modelling bug, and it is now a
    # visible, stable one rather than a silently unstable hash.
    if _DEFAULT_REPR.match(text):
        return f"<unserialisable {type(value).__module__}.{type(value).__qualname__}>"
    return text


class TargetType(str, Enum):
    """Kinds of subject an action or verification can be directed at."""

    ACCESS_POINT = "access_point"
    CLIENT = "client"
    INTERFACE = "interface"
    NETWORK = "network"
    HOST = "host"
    SERVICE = "service"
    DOMAIN = "domain"
    FINDING = "finding"
    HYPOTHESIS = "hypothesis"
    OBSERVATION = "observation"
    CAPTURE = "capture"
    #: No specific subject (e.g. environment-wide interface discovery).
    NONE = "none"


@dataclass(frozen=True)
class EntityRef:
    """
    A reference to something the World Model knows about.

    ``id`` is the World Model's stable identifier for the entity (a BSSID, a MAC, an IP, an
    interface name, or a finding/hypothesis UUID). ``label`` carries a human-readable
    descriptor without being part of the identity.
    """

    type: str
    id: Optional[str] = None
    label: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.type, "id": self.id, "label": self.label}

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "EntityRef":
        if data is None:
            return cls(type=TargetType.NONE.value)
        if not isinstance(data, dict):
            raise TypeError("EntityRef requires a JSON object")
        return cls(type=str(data.get("type") or TargetType.NONE.value), id=data.get("id"), label=data.get("label"))

    @property
    def is_empty(self) -> bool:
        return self.type == TargetType.NONE.value and not self.id


@dataclass(frozen=True)
class Provenance:
    """Where a piece of evidence came from, in PROV terms."""

    execution_id: Optional[str] = None
    action_id: Optional[str] = None
    verification_id: Optional[str] = None
    assessment_id: Optional[str] = None
    correlation_id: Optional[str] = None
    tool: Optional[str] = None
    capability: Optional[str] = None
    interface: Optional[str] = None
    raw_command: Optional[str] = None
    #: Artifact identifiers this observation was derived from (PROV ``wasDerivedFrom``).
    derived_from: List[str] = field(default_factory=list)
    parser: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "action_id": self.action_id,
            "verification_id": self.verification_id,
            "assessment_id": self.assessment_id,
            "correlation_id": self.correlation_id,
            "tool": self.tool,
            "capability": self.capability,
            "interface": self.interface,
            "raw_command": self.raw_command,
            "derived_from": list(self.derived_from),
            "parser": self.parser,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "Provenance":
        data = data or {}
        return cls(
            execution_id=data.get("execution_id"),
            action_id=data.get("action_id"),
            verification_id=data.get("verification_id"),
            assessment_id=data.get("assessment_id"),
            correlation_id=data.get("correlation_id"),
            tool=data.get("tool"),
            capability=data.get("capability"),
            interface=data.get("interface"),
            raw_command=data.get("raw_command"),
            derived_from=list(data.get("derived_from") or []),
            parser=data.get("parser"),
        )


@dataclass(frozen=True)
class ArtifactRef:
    """
    A reference to bytes produced or consumed by an execution.

    The payload itself is never inlined in a contract message: large captures and verbose
    tool output are stored by the artifact store and referenced by identifier, so messages
    stay small and the raw bytes stay intact and verifiable via ``sha256``.
    """

    id: str
    kind: str  # stdout | stderr | pcap | csv | file | json
    path: Optional[str] = None
    sha256: Optional[str] = None
    bytes: int = 0
    created_at: Optional[str] = None
    truncated: bool = False
    media_type: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "path": self.path,
            "sha256": self.sha256,
            "bytes": self.bytes,
            "created_at": self.created_at,
            "truncated": self.truncated,
            "media_type": self.media_type,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ArtifactRef":
        return cls(
            id=str(data["id"]),
            kind=str(data.get("kind") or "file"),
            path=data.get("path"),
            sha256=data.get("sha256"),
            bytes=int(data.get("bytes") or 0),
            created_at=data.get("created_at"),
            truncated=bool(data.get("truncated", False)),
            media_type=data.get("media_type"),
            description=data.get("description"),
        )


@dataclass(frozen=True)
class ToolRef:
    """The real tool that was invoked, as reported by the Execution Engine."""

    name: str
    version: Optional[str] = None
    path: Optional[str] = None
    #: Adapter that translated the ActionRequest into the invocation.
    adapter: Optional[str] = None
    adapter_version: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "path": self.path,
            "adapter": self.adapter,
            "adapter_version": self.adapter_version,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> Optional["ToolRef"]:
        if not data:
            return None
        return cls(
            name=str(data.get("name") or "unknown"),
            version=data.get("version"),
            path=data.get("path"),
            adapter=data.get("adapter"),
            adapter_version=data.get("adapter_version"),
        )


@dataclass(frozen=True)
class InterfaceRef:
    """The wireless interface an execution used, with the capabilities it was observed to have."""

    name: str
    driver: Optional[str] = None
    chipset: Optional[str] = None
    mac: Optional[str] = None
    is_up: Optional[bool] = None
    capabilities: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "driver": self.driver,
            "chipset": self.chipset,
            "mac": self.mac,
            "is_up": self.is_up,
            "capabilities": list(self.capabilities),
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> Optional["InterfaceRef"]:
        if not data:
            return None
        return cls(
            name=str(data.get("name")),
            driver=data.get("driver"),
            chipset=data.get("chipset"),
            mac=data.get("mac"),
            is_up=data.get("is_up"),
            capabilities=list(data.get("capabilities") or []),
        )


@dataclass(frozen=True)
class ParserRef:
    """Identifies the evidence parser that produced an EvidenceSet."""

    name: str
    version: str = "1.0"

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "version": self.version}

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> Optional["ParserRef"]:
        if not data:
            return None
        return cls(name=str(data.get("name") or "unknown"), version=str(data.get("version") or "1.0"))
