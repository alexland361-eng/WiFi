"""
Dependency Resolver - Resolves tool dependencies and execution order.

Handles tool chains and prerequisites for assessment objectives.

Deep research: Tools have dependencies (e.g., airmon-ng needs iw, hashcat needs hash file from hcxpcapngtool, etc.)
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from ..models.capability import ToolCapabilityMetadata
from .registry import CapabilityRegistry


class DependencyResolver:
    """Resolves dependencies and execution order for tool chains."""

    def __init__(self, registry: CapabilityRegistry):
        self.registry = registry

    def resolve_dependencies(self, capability_name: str, visited: Set[str] = None) -> Tuple[List[str], List[str]]:
        """
        Resolve dependencies for capability.

        Returns (ordered_dependencies, missing_dependencies)
        """
        visited = visited or set()
        ordered = []
        missing = []

        if capability_name in visited:
            return ordered, missing  # Avoid cycles

        visited.add(capability_name)

        meta = self.registry.get_metadata(capability_name)
        if not meta:
            missing.append(capability_name)
            return ordered, missing

        # Check tool dependencies
        for dep_binary in meta.requirements.dependencies:
            # Find capability that provides this binary
            provider = None
            for cap_name in self.registry.list_capabilities():
                cap_meta = self.registry.get_metadata(cap_name)
                if cap_meta and cap_meta.tool_binary == dep_binary:
                    provider = cap_name
                    break

            if provider:
                # Recursively resolve provider's dependencies
                dep_ordered, dep_missing = self.resolve_dependencies(provider, visited.copy())
                for dep in dep_ordered:
                    if dep not in ordered:
                        ordered.append(dep)
                missing.extend(dep_missing)
                if provider not in ordered:
                    ordered.append(provider)
            else:
                # Dependency is a binary, not a capability - check if available via which
                from ...utils.system import check_tool_available

                available, _, _ = check_tool_available(dep_binary)
                if not available:
                    missing.append(dep_binary)

        # Add self after dependencies
        if capability_name not in ordered:
            ordered.append(capability_name)

        return ordered, missing

    def get_execution_plan(self, objectives: List[str], available_capabilities: Dict[str, ToolCapabilityMetadata] = None) -> List[Dict[str, Any]]:
        """
        Get execution plan for objectives.

        Objectives are high-level goals like "handshake_capture", "wps_assessment", etc.
        Returns ordered list of capability executions with dependencies resolved.
        """
        from .tool_manager import ToolManager

        # Tool chains per objective (from ToolManager)
        tool_manager = ToolManager(self.registry)
        all_capabilities = []

        for objective in objectives:
            chain = tool_manager.get_tool_chain(objective)
            all_capabilities.extend(chain)

        # Remove duplicates while preserving order
        seen = set()
        unique_caps = []
        for cap in all_capabilities:
            if cap not in seen:
                seen.add(cap)
                unique_caps.append(cap)

        # Resolve dependencies for each
        ordered_plan = []
        visited = set()

        for cap_name in unique_caps:
            deps, missing = self.resolve_dependencies(cap_name, visited.copy())
            for dep in deps:
                if dep not in [p["capability"] for p in ordered_plan]:
                    ordered_plan.append(
                        {
                            "capability": dep,
                            "dependencies": [],
                            "missing": [],
                            "objective": objectives,
                        }
                    )
                visited.add(dep)

        # Filter to only available capabilities if provided
        if available_capabilities is not None:
            filtered_plan = []
            for item in ordered_plan:
                if item["capability"] in available_capabilities:
                    filtered_plan.append(item)
            ordered_plan = filtered_plan

        return ordered_plan

    def check_tool_chain_feasibility(self, chain: List[str], interface: str = None) -> Tuple[bool, List[str], Dict[str, str]]:
        """
        Check if tool chain is feasible in current environment.

        Returns (feasible, missing_tools, reasons)
        """
        missing = []
        reasons = {}

        for cap_name in chain:
            meta = self.registry.get_metadata(cap_name)
            if not meta:
                missing.append(cap_name)
                reasons[cap_name] = "Not registered"
                continue

            # Check availability
            ok, reason, _ = self.registry.check_availability(cap_name, interface)
            if not ok:
                missing.append(cap_name)
                reasons[cap_name] = reason

        feasible = len(missing) == 0
        return feasible, missing, reasons

    def suggest_alternatives(self, capability_name: str, available_capabilities: Dict[str, ToolCapabilityMetadata]) -> List[str]:
        """
        Suggest alternative capabilities that produce similar outputs.

        Example: If airodump-ng not available, suggest tshark, kismet, horst, etc.
        """
        meta = self.registry.get_metadata(capability_name)
        if not meta:
            return []

        target_outputs = set(meta.outputs)
        alternatives = []

        for cap_name, cap_meta in available_capabilities.items():
            if cap_name == capability_name:
                continue

            # Check output overlap
            overlap = target_outputs.intersection(set(cap_meta.outputs))
            if overlap:
                alternatives.append((cap_name, len(overlap)))

        # Sort by overlap count descending
        alternatives.sort(key=lambda x: x[1], reverse=True)
        return [cap_name for cap_name, _ in alternatives]

    def to_dict(self) -> Dict[str, Any]:
        """Export for audit."""
        return {
            "total_capabilities": len(self.registry.list_capabilities()),
            "tool_chains": {
                "handshake_capture": ["airodump-ng", "hcxdumptool", "hcxpcapngtool"],
                "wpa_crack": ["hcxpcapngtool", "hashcat", "john", "aircrack-ng"],
                "wps_assessment": ["wash", "reaver", "bully", "pixiewps"],
                "wireless_discovery": ["iw_dev", "iwconfig", "rfkill", "iw_list", "airodump-ng", "kismet"],
                "network_discovery": ["arp-scan", "netdiscover", "fping", "nmap"],
            },
        }
