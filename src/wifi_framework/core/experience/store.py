"""
Experience store - maintains experience record describing previous actions,
state in which they were executed, parameters, results, information gain,
execution cost, and whether subsequent verification supported conclusion.

This experience can later be used by heuristic planners, statistical models,
or optional AI-based decision systems to improve future action selection.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class ExperienceRecord:
    """Single experience record."""

    id: str
    timestamp: str
    capability_name: str
    tool_binary: str
    interface: Optional[str]
    parameters: Dict[str, Any]
    state_summary: Dict[str, Any]
    uncertainty_type: Optional[str]
    success: bool
    exit_code: Optional[int]
    duration_seconds: float
    evidence_count: int
    information_gain: float
    cost: float
    failure_reason: Optional[str]
    verification_supported: Optional[bool] = None
    tags: List[str] = field(default_factory=list)


class ExperienceStore:
    """Stores and manages experience for learning."""

    def __init__(self, store_path: str = "/tmp/wifi_framework_experience.jsonl"):
        self.store_path = store_path
        self.experiences: List[ExperienceRecord] = []
        self._load()

    def _load(self):
        """Load existing experiences from file."""
        if not os.path.exists(self.store_path):
            return
        try:
            with open(self.store_path, "r") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        record = ExperienceRecord(**data)
                        self.experiences.append(record)
                    except (json.JSONDecodeError, TypeError):
                        continue
        except OSError:
            pass

    def add(
        self,
        capability_name: str,
        tool_binary: str,
        interface: Optional[str],
        parameters: Dict[str, Any],
        state_summary: Dict[str, Any],
        uncertainty_type: Optional[str],
        success: bool,
        exit_code: Optional[int],
        duration_seconds: float,
        evidence_count: int,
        failure_reason: Optional[str] = None,
    ) -> ExperienceRecord:
        """Add new experience record."""
        # Calculate information gain and cost
        # Information gain = evidence count weighted by success
        info_gain = float(evidence_count) if success else 0.0
        # Cost = duration + penalty for failure
        cost = duration_seconds
        if not success:
            cost += 10.0  # Penalty

        record = ExperienceRecord(
            id=f"{capability_name}_{datetime.now(timezone.utc).timestamp()}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            capability_name=capability_name,
            tool_binary=tool_binary,
            interface=interface,
            parameters=parameters,
            state_summary=state_summary,
            uncertainty_type=uncertainty_type,
            success=success,
            exit_code=exit_code,
            duration_seconds=duration_seconds,
            evidence_count=evidence_count,
            information_gain=info_gain,
            cost=cost,
            failure_reason=failure_reason,
        )

        self.experiences.append(record)

        # Persist
        try:
            os.makedirs(os.path.dirname(self.store_path), exist_ok=True)
            with open(self.store_path, "a") as f:
                f.write(json.dumps(asdict(record)) + "\n")
        except OSError:
            pass

        return record

    def get_capability_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics per capability for heuristic planning."""
        stats = {}
        for exp in self.experiences:
            cap = exp.capability_name
            if cap not in stats:
                stats[cap] = {
                    "total_executions": 0,
                    "success_count": 0,
                    "total_info_gain": 0.0,
                    "total_cost": 0.0,
                    "avg_duration": 0.0,
                    "success_rate": 0.0,
                    "avg_info_gain": 0.0,
                }
            stats[cap]["total_executions"] += 1
            if exp.success:
                stats[cap]["success_count"] += 1
            stats[cap]["total_info_gain"] += exp.information_gain
            stats[cap]["total_cost"] += exp.cost

        for cap, data in stats.items():
            if data["total_executions"] > 0:
                data["success_rate"] = data["success_count"] / data["total_executions"]
                data["avg_info_gain"] = data["total_info_gain"] / data["total_executions"]
                data["avg_duration"] = data["total_cost"] / data["total_executions"]

        return stats

    def get_experience_scores(self) -> Dict[str, float]:
        """
        Get experience scores for action selection.

        Score = (avg_info_gain * success_rate) / avg_duration
        Higher is better.
        """
        stats = self.get_capability_stats()
        scores = {}
        for cap, data in stats.items():
            if data["avg_duration"] > 0:
                score = (data["avg_info_gain"] * data["success_rate"]) / (data["avg_duration"] / 10.0 + 1.0)
                scores[cap] = score
            else:
                scores[cap] = data["avg_info_gain"] * data["success_rate"]
        return scores

    def update_verification(self, capability_name: str, verification_supported: bool):
        """Update last experience for capability with verification result."""
        # Find most recent experience for this capability
        for exp in reversed(self.experiences):
            if exp.capability_name == capability_name and exp.verification_supported is None:
                exp.verification_supported = verification_supported
                break

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_experiences": len(self.experiences),
            "capability_stats": self.get_capability_stats(),
            "experience_scores": self.get_experience_scores(),
            "recent_experiences": [asdict(e) for e in self.experiences[-10:]],
        }
