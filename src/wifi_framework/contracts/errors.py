"""
Contract errors.

Every contract failure is raised as a typed error so that consumers can distinguish
"the producer sent something I cannot interpret" (a contract violation, which must halt
processing of that message) from "the operation did not succeed" (an ordinary execution
failure, which is represented inside the ExecutionResult contract and must never raise).
"""
from __future__ import annotations

from typing import List, Optional


class ContractError(Exception):
    """Base class for all contract violations."""

    def __init__(self, message: str, *, schema: Optional[str] = None, version: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.schema = schema
        self.version = version


class ContractValidationError(ContractError):
    """A message failed structural or semantic validation."""

    def __init__(self, message: str, issues: Optional[List[str]] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.issues: List[str] = list(issues or [])


class UnsupportedContractVersion(ContractError):
    """
    A producer sent a major version this consumer does not support.

    Per the specification, consumers must reject unsupported major versions rather than
    silently interpreting incompatible data.
    """

    def __init__(self, schema: str, version: str, supported: List[str]):
        super().__init__(
            f"Contract '{schema}' version '{version}' is not supported; "
            f"this consumer supports major versions {supported}",
            schema=schema,
            version=version,
        )
        self.supported = list(supported)


class UnknownContractSchema(ContractError):
    """The message names a schema this consumer has never registered."""

    def __init__(self, schema: str):
        super().__init__(f"Unknown contract schema '{schema}'", schema=schema)
        self.schema = schema


class ContractOwnershipError(ContractError):
    """A consumer attempted to mutate or re-publish a contract it does not own."""
