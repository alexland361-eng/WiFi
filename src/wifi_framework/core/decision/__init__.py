"""
Decision Engine subsystem.

Consumes the ``world-state`` contract and produces ``action-request`` messages. It also owns the
optional AI boundary: it publishes a constrained ``planning-context`` and converts an accepted
``decision-proposal`` into an ordinary action request that still has to pass policy validation.

Specification section 19: "The Execution Engine does not know why the planner selected an
action." The reasoning travels only inside ``ActionRequest.reason``, which is a record, not an
instruction.
"""
from __future__ import annotations

from .engine import DecisionEngine
from .state_view import ContractRegistryView, ViewExecution, ViewScope, ViewWorldModel, WorldStateView

__all__ = [
    "DecisionEngine",
    "WorldStateView",
    "ContractRegistryView",
    "ViewWorldModel",
    "ViewScope",
    "ViewExecution",
]
