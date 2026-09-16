"""
Capability registry - loads tool definitions, adapters.

Treats tools as specialized instruments rather than interchangeable command wrappers.
Each tool registered with capabilities, prerequisites, input params, output formats,
operational characteristics, types of evidence it can produce.
"""
from __future__ import annotations

import importlib
import pkgutil
from typing import Dict, List, Optional, Type

from ..models.capability import ToolCapabilityMetadata
from .adapter_base import ToolAdapterBase
from .capability_checker import CapabilityChecker


class CapabilityRegistry:
    """Registry of all tool capabilities."""

    def __init__(self):
        self._capabilities: Dict[str, ToolCapabilityMetadata] = {}
        self._adapters: Dict[str, Type[ToolAdapterBase]] = {}
        self._checker = CapabilityChecker()

    def register(self, metadata: ToolCapabilityMetadata, adapter_class: Type[ToolAdapterBase]):
        """Register a capability with its adapter."""
        if not issubclass(adapter_class, ToolAdapterBase):
            raise ValueError(f"Adapter {adapter_class} must subclass ToolAdapterBase")
        self._capabilities[metadata.name] = metadata
        self._adapters[metadata.name] = adapter_class

    def get_metadata(self, name: str) -> Optional[ToolCapabilityMetadata]:
        return self._capabilities.get(name)

    def get_adapter_class(self, name: str) -> Optional[Type[ToolAdapterBase]]:
        return self._adapters.get(name)

    def get_adapter_instance(self, name: str) -> Optional[ToolAdapterBase]:
        """Create adapter instance for capability."""
        metadata = self.get_metadata(name)
        adapter_class = self.get_adapter_class(name)
        if not metadata or not adapter_class:
            return None
        return adapter_class(metadata)

    def list_capabilities(self) -> List[str]:
        return list(self._capabilities.keys())

    def list_by_category(self, category) -> List[ToolCapabilityMetadata]:
        return [cap for cap in self._capabilities.values() if cap.category == category]

    def check_availability(self, name: str, interface: str = None):
        """Check if capability is available in current environment."""
        metadata = self.get_metadata(name)
        if not metadata:
            return False, f"Capability {name} not registered", {}
        return self._checker.check(metadata, interface)

    def get_available_capabilities(self, interface: str = None) -> Dict[str, ToolCapabilityMetadata]:
        """Get all capabilities available in current environment."""
        available = {}
        for name, meta in self._capabilities.items():
            ok, _, _ = self._checker.check(meta, interface)
            if ok:
                available[name] = meta
        return available

    def get_unavailable_capabilities(self, interface: str = None) -> Dict[str, str]:
        """Get unavailable capabilities with reasons."""
        unavailable = {}
        for name, meta in self._capabilities.items():
            ok, reason, _ = self._checker.check(meta, interface)
            if not ok:
                unavailable[name] = reason
        return unavailable

    def auto_discover_adapters(self, package_name: str = "wifi_framework.tools.adapters"):
        """
        Auto-discover adapters from package.

        Each adapter module should expose METADATA and ADAPTER_CLASS or register via function.
        """
        try:
            package = importlib.import_module(package_name)
        except ImportError:
            return

        # Walk through subpackages
        for _, mod_name, is_pkg in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
            if is_pkg:
                continue
            try:
                module = importlib.import_module(mod_name)
                # Look for registration
                if hasattr(module, "METADATA") and hasattr(module, "ADAPTER_CLASS"):
                    self.register(module.METADATA, module.ADAPTER_CLASS)
                elif hasattr(module, "register"):
                    # Module provides register function
                    module.register(self)
            except Exception as e:
                # Don't fail on single adapter import error, but log
                print(f"Warning: Failed to load adapter module {mod_name}: {e}")
                continue


# Global registry instance
_global_registry: Optional[CapabilityRegistry] = None


def get_global_registry() -> CapabilityRegistry:
    global _global_registry
    if _global_registry is None:
        _global_registry = CapabilityRegistry()
        # Auto-discover
        _global_registry.auto_discover_adapters()
    return _global_registry
