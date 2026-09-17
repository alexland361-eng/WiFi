"""
WiFi Framework - Real Wi-Fi penetration-testing and security-assessment framework.

Operational Philosophy:
This project is designed as a real Wi-Fi penetration-testing and security-assessment framework,
not as a collection of simulated demonstrations, command wrappers, or placeholder tool integrations.
Its purpose is to perform genuine assessments against networks and wireless environments for which
the operator has explicit authorization.

The framework treats Wi-Fi penetration testing as an adaptive investigation rather than a fixed
sequence of commands. It continuously maintains an internal model of the observed wireless environment,
determines what information is currently known, identifies important uncertainties, evaluates which
available action can provide useful additional evidence, and then selects and executes that action.
"""

__version__ = "0.5.0"
__author__ = "WiFi Framework Team"

from .core.models import (
    AssessmentPhase,
    AssessmentScope,
    AssessmentState,
    ConfidenceLevel,
    Evidence,
    EvidenceType,
    Finding,
    FindingStatus,
    ToolCapabilityMetadata,
    WorldModel,
)
from .core.engine import AssessmentEngine
from .core.execution import CapabilityRegistry, get_global_registry

__all__ = [
    "__version__",
    "AssessmentEngine",
    "AssessmentState",
    "AssessmentPhase",
    "AssessmentScope",
    "Evidence",
    "EvidenceType",
    "ConfidenceLevel",
    "Finding",
    "FindingStatus",
    "ToolCapabilityMetadata",
    "WorldModel",
    "CapabilityRegistry",
    "get_global_registry",
]
