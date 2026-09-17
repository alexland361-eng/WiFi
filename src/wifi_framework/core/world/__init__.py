"""
World Model subsystem boundary.

The World Model's data structures live in :mod:`wifi_framework.core.models` (unchanged since
v0.1.0). This package is its **contract boundary**: it owns production of the ``world-state``
message and consumption of ``evidence-set`` and ``verification-result`` messages.

Specification section 19: "The World Model does not know how a tool was executed." Nothing in
this package imports the execution layer.
"""
from __future__ import annotations

from .applier import VERIFICATION_TO_FINDING_STATUS, ApplyReport, WorldModelApplier
from .state_publisher import (
    CLOSED_STATUSES,
    DEFAULT_STALENESS_SECONDS,
    OPEN_STATUSES,
    WorldStatePublisher,
    uncertainty_id,
)

__all__ = [
    "WorldStatePublisher",
    "WorldModelApplier",
    "ApplyReport",
    "uncertainty_id",
    "DEFAULT_STALENESS_SECONDS",
    "OPEN_STATUSES",
    "CLOSED_STATUSES",
    "VERIFICATION_TO_FINDING_STATUS",
]
