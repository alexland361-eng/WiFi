"""
Contract registry and version negotiation.

Every consumer validates an incoming message against this registry before interpreting it.
The rule from the specification — "Consumers must reject unsupported major versions rather
than silently interpreting incompatible data" — is implemented as a hard failure
(:class:`~wifi_framework.contracts.errors.UnsupportedContractVersion`) rather than a warning,
because a silently misread contract produces assessment conclusions that cannot be trusted.

Registration is per (schema, major version). Minor versions are accepted automatically within
a supported major, since Semantic Versioning defines a minor bump as a backward-compatible
addition; unknown optional fields survive via ``BaseContract.extensions``.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Type

from .envelope import ContractVersion
from .errors import UnknownContractSchema, UnsupportedContractVersion


class ContractRegistry:
    """Registry of the contract schemas and major versions this build understands."""

    def __init__(self) -> None:
        self._majors: Dict[str, List[int]] = {}
        self._classes: Dict[Tuple[str, int], Type[Any]] = {}
        self._producers: Dict[str, str] = {}

    def register(self, schema: str, version: str, contract_class: Optional[Type[Any]] = None, producer: str = "") -> None:
        """Declare that this build supports ``schema`` at the given ``MAJOR.MINOR`` version."""
        parsed = ContractVersion.parse(version)
        majors = self._majors.setdefault(schema, [])
        if parsed.major not in majors:
            majors.append(parsed.major)
            majors.sort()
        if contract_class is not None:
            self._classes[(schema, parsed.major)] = contract_class
        if producer:
            self._producers[schema] = producer

    def supported_majors(self, schema: str) -> List[int]:
        return list(self._majors.get(schema, []))

    def known_schemas(self) -> List[str]:
        return sorted(self._majors)

    def is_supported(self, schema: str, version: str) -> bool:
        try:
            parsed = ContractVersion.parse(version)
        except Exception:
            return False
        return parsed.major in self._majors.get(schema, [])

    def assert_supported(self, schema: str, version: str) -> ContractVersion:
        """Raise unless ``schema``/``version`` can be interpreted by this consumer."""
        if schema not in self._majors:
            raise UnknownContractSchema(schema)
        parsed = ContractVersion.parse(version)
        if parsed.major not in self._majors[schema]:
            raise UnsupportedContractVersion(
                schema, version, [f"{major}.x" for major in self._majors[schema]]
            )
        return parsed

    def negotiate(self, schema: str, version: str) -> Tuple[bool, str]:
        """Non-raising variant used when reporting capability rather than processing a message."""
        try:
            self.assert_supported(schema, version)
            return True, f"{schema} {version} is supported"
        except (UnknownContractSchema, UnsupportedContractVersion) as exc:
            return False, str(exc)

    def class_for(self, schema: str, version: str) -> Optional[Type[Any]]:
        """Return the contract class implementing ``schema`` at this major version."""
        try:
            parsed = ContractVersion.parse(version)
        except Exception:
            return None
        return self._classes.get((schema, parsed.major))

    def producer_of(self, schema: str) -> Optional[str]:
        return self._producers.get(schema)

    def describe(self) -> Dict[str, Any]:
        """Machine-readable description, included in audit reports."""
        return {
            schema: {
                "supported_major_versions": list(majors),
                "producer": self._producers.get(schema),
            }
            for schema, majors in sorted(self._majors.items())
        }


_registry: Optional[ContractRegistry] = None


def build_default_registry() -> ContractRegistry:
    """
    Register every contract this build produces or consumes, at version 1.0.

    Imports are local so that ``contracts.base`` can call into the registry without creating
    an import cycle.
    """
    from .action import ActionRequest, ActionValidationResult
    from .ai import DecisionProposal, PlanningContext
    from .evidence import EvidenceSet
    from .execution import ExecutionResult
    from .experience import ExperienceRecord
    from .verification import VerificationRequest, VerificationResult
    from .world_state import WorldState

    registry = ContractRegistry()
    for contract_class in (
        WorldState,
        ActionRequest,
        ActionValidationResult,
        ExecutionResult,
        EvidenceSet,
        VerificationRequest,
        VerificationResult,
        ExperienceRecord,
        PlanningContext,
        DecisionProposal,
    ):
        registry.register(contract_class.SCHEMA, contract_class.VERSION, contract_class, contract_class.PRODUCER)
    return registry


def get_contract_registry() -> ContractRegistry:
    """Return the process-wide default contract registry, building it on first use."""
    global _registry
    if _registry is None:
        _registry = build_default_registry()
    return _registry


def reset_contract_registry() -> None:
    """Drop the cached registry (used by tests that register experimental versions)."""
    global _registry
    _registry = None
