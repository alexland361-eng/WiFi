"""
Base class for tool adapters.

Architecture:
Raw tool -> Adapter -> Capability -> Structured observations -> World model

Adapter responsibilities:
- Translate structured parameters from decision engine into valid tool invocations
- Convert resulting output into structured observations
- Check requirements
- Handle failures
"""
from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from ..models.capability import ToolCapabilityMetadata
from ..models.evidence import Evidence, EvidenceType
from ...utils.system import check_interface_exists, check_tool_available, get_os_info, is_root, run_command
from ...utils.validation import validate_interface, validate_parameters


class AdapterExecutionResult:
    """Result of adapter execution."""

    def __init__(
        self,
        success: bool,
        raw_output: str = "",
        error_output: str = "",
        exit_code: int = 0,
        duration: float = 0.0,
        evidences: List[Evidence] = None,
        failure_reason: Optional[str] = None,
        raw_command: str = "",
    ):
        self.success = success
        self.raw_output = raw_output
        self.error_output = error_output
        self.exit_code = exit_code
        self.duration = duration
        self.evidences = evidences or []
        self.failure_reason = failure_reason
        self.raw_command = raw_command


class ToolAdapterBase(ABC):
    """
    Base class for all tool adapters.

    Every operational capability must correspond to functioning implementation.
    Placeholder adapters are not allowed - if capability unavailable, report explicitly.
    """

    def __init__(self, metadata: ToolCapabilityMetadata):
        self.metadata = metadata
        self.execution_id = str(uuid.uuid4())

    @property
    def name(self) -> str:
        return self.metadata.name

    @property
    def tool_binary(self) -> str:
        return self.metadata.tool_binary

    def check_requirements(
        self, interface: Optional[str] = None, parameters: Dict[str, Any] = None
    ) -> Tuple[bool, str]:
        """
        Verify that selected wireless interface, OS, driver, privileges, tool version,
        and current environment satisfy action's requirements.

        Returns (is_satisfied, reason)
        """
        parameters = parameters or {}

        # Check OS
        os_info = get_os_info()
        if not self.metadata.is_compatible_with_os(os_info["system"]):
            return False, f"Incompatible OS: {os_info['system']} not in {self.metadata.requirements.operating_systems}"

        # Check tool availability
        available, path, version_info = check_tool_available(self.tool_binary)
        if not available:
            return False, f"Tool binary '{self.tool_binary}' not available: {version_info}"

        # Check version if required
        if self.metadata.requirements.min_tool_version and version_info:
            from ...utils.system import is_version_sufficient

            if not is_version_sufficient(version_info, self.metadata.requirements.min_tool_version):
                return False, f"Tool version insufficient: need {self.metadata.requirements.min_tool_version}, got {version_info}"

        # Check interface if required
        if self.metadata.requirements.interface_required:
            if not interface:
                return False, "Interface required but not provided"
            if not check_interface_exists(interface):
                return False, f"Interface '{interface}' does not exist"

        # Check privileges
        if "root" in self.metadata.requirements.privileges:
            if not is_root():
                return False, "Root privileges required but not running as root"

        # Check dependencies
        for dep in self.metadata.requirements.dependencies:
            dep_available, _, _ = check_tool_available(dep)
            if not dep_available:
                return False, f"Dependency '{dep}' not available"

        # Custom checks from subclass
        custom_ok, custom_reason = self.custom_requirement_check(interface, parameters)
        if not custom_ok:
            return False, custom_reason

        return True, "Requirements satisfied"

    def custom_requirement_check(
        self, interface: Optional[str], parameters: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """Override for adapter-specific checks."""
        return True, ""

    def validate_parameters(self, parameters: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate input parameters."""
        # Check required inputs from metadata
        required = [inp for inp in self.metadata.inputs if not inp.startswith("optional_")]
        # Allow subclass to define required
        return self.custom_parameter_validation(parameters)

    def custom_parameter_validation(self, parameters: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Override for custom validation. Default checks metadata inputs."""
        # By default, ensure all metadata inputs that are required are present
        # For flexibility, we don't enforce strictly here - subclass should override
        return True, []

    @abstractmethod
    def build_command(self, interface: Optional[str], parameters: Dict[str, Any]) -> List[str]:
        """
        Translate structured parameters into valid tool invocation.

        Must return list of command args (not shell string) for security.
        """
        pass

    @abstractmethod
    def parse_output(
        self, raw_output: str, error_output: str, exit_code: int, parameters: Dict[str, Any], interface: Optional[str]
    ) -> List[Evidence]:
        """
        Convert raw tool output into structured observations.

        Must never fabricate discoveries or pretend attack succeeded.
        """
        pass

    def execute(
        self, interface: Optional[str] = None, parameters: Dict[str, Any] = None, timeout: int = 30
    ) -> AdapterExecutionResult:
        """
        Execute the tool with real underlying utility against real wireless interface.

        Handles parameter generation, validation, execution, timeout, output collection, failure reporting.
        """
        parameters = parameters or {}
        self.execution_id = str(uuid.uuid4())

        # Validate parameters
        valid, errors = self.validate_parameters(parameters)
        if not valid:
            return AdapterExecutionResult(
                success=False,
                failure_reason=f"Parameter validation failed: {'; '.join(errors)}",
                raw_output="",
                error_output="; ".join(errors),
            )

        # Validate the interface name whenever one is supplied, not only when the
        # capability declares an interface mandatory. The name is interpolated into
        # argv and into /sys/class/net/<name> paths, so an unchecked value is a
        # traversal and argument-smuggling risk. Capabilities with
        # interface_required=False still accept an interface argument and hand it
        # straight to build_command, which previously left it unvalidated.
        #
        # This is defence in depth rather than a live exploit: argv is a list and
        # nothing in src/ uses shell=True, so a ';' reaches the tool as a literal
        # character. ActionPolicy also validates `interface` before dispatch, so
        # the policy-gated path was already covered - but an adapter invoked
        # directly was not, and the base class is the one place that covers all of
        # them.
        if interface:
            iface_ok, iface_reason = validate_interface(interface)
            if not iface_ok:
                return AdapterExecutionResult(
                    success=False,
                    failure_reason=f"Interface validation failed: {iface_reason}",
                    raw_output="",
                    error_output=iface_reason,
                )

        # Check requirements
        req_ok, req_reason = self.check_requirements(interface, parameters)
        if not req_ok:
            return AdapterExecutionResult(
                success=False,
                failure_reason=f"Requirements not met: {req_reason}",
                raw_output="",
                error_output=req_reason,
            )

        # Build command
        try:
            cmd = self.build_command(interface, parameters)
            if not cmd or not isinstance(cmd, list):
                return AdapterExecutionResult(
                    success=False,
                    failure_reason="Failed to build valid command",
                    raw_output="",
                    error_output="build_command returned invalid result",
                )
            raw_command_str = " ".join(cmd)
        except Exception as e:
            return AdapterExecutionResult(
                success=False,
                failure_reason=f"Command building failed: {e}",
                raw_output="",
                error_output=str(e),
            )

        # Execute real tool
        start = time.time()
        try:
            exit_code, stdout, stderr, duration = run_command(cmd, timeout=timeout)
        except Exception as e:
            return AdapterExecutionResult(
                success=False,
                failure_reason=f"Execution exception: {e}",
                raw_output="",
                error_output=str(e),
                raw_command=raw_command_str,
                duration=time.time() - start,
            )

        # Parse output
        try:
            evidences = self.parse_output(stdout, stderr, exit_code, parameters, interface)
            # Tag evidences with execution_id
            for ev in evidences:
                ev.execution_id = self.execution_id
                if not ev.interface and interface:
                    ev.interface = interface
        except Exception as e:
            return AdapterExecutionResult(
                success=False,
                failure_reason=f"Output parsing failed: {e}",
                raw_output=stdout,
                error_output=stderr + f"\nParser error: {e}",
                exit_code=exit_code,
                duration=duration,
                raw_command=raw_command_str,
            )

        success = exit_code == 0
        failure_reason = None
        if not success:
            # Determine failure reason from metadata failure conditions
            failure_reason = self.interpret_failure(exit_code, stdout, stderr)

        return AdapterExecutionResult(
            success=success,
            raw_output=stdout,
            error_output=stderr,
            exit_code=exit_code,
            duration=duration,
            evidences=evidences,
            failure_reason=failure_reason,
            raw_command=raw_command_str,
        )

    def interpret_failure(self, exit_code: int, stdout: str, stderr: str) -> Optional[str]:
        """Interpret failure based on exit code and output."""
        combined = (stdout + " " + stderr).lower()
        for condition in self.metadata.failure_conditions:
            if condition == "interface_unavailable" and ("no such device" in combined or "interface" in combined and "not found" in combined):
                return "interface_unavailable"
            if condition == "insufficient_privileges" and ("permission denied" in combined or "must be root" in combined or "operation not permitted" in combined):
                return "insufficient_privileges"
            if condition == "unsupported_driver" and ("driver" in combined and "not supported" in combined):
                return "unsupported_driver"
        if exit_code == 127:
            return "tool_not_found"
        if exit_code == 124:
            return "timeout"
        if exit_code != 0:
            return f"tool_failed_exit_{exit_code}"
        return None
