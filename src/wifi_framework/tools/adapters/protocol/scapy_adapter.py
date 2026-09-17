"""
Adapter for Scapy - programmable packet manipulation and analysis framework.

Unlike the command-line utilities, Scapy is a Python library, so this adapter
calls its API in-process rather than spawning a binary.

Security boundary
-----------------
An earlier version of this adapter accepted a ``script`` parameter and ran it
through ``exec()`` with full ``__builtins__``. That made the capability an
arbitrary-code-execution primitive: the policy layer's rejection of shell
metacharacters could not apply, because pure Python needs none, and the
no-``shell=True`` AST sweep could not apply either, because no shell was
involved. A payload as simple as ``open('/tmp/x','w').write('...')`` ran while
the adapter reported failure.

It is now a bounded, declarative operation set. Callers choose an operation and
supply validated scalars; they never supply code. Executing a caller-supplied
string as code is not something an autonomous assessment loop should be able to
request, whatever the sandbox around it - so the ``script`` parameter is rejected
outright rather than restricted.
"""
from __future__ import annotations

from importlib.util import find_spec
from typing import Any, Dict, List, Optional, Tuple

# Absolute imports throughout: a wrong relative-import depth here previously
# raised ModuleNotFoundError, which the broad `except ImportError` below then
# misreported as a missing dependency.
from wifi_framework.core.execution.adapter_base import AdapterExecutionResult, ToolAdapterBase
from wifi_framework.core.models.capability import (
    CapabilityCategory,
    CapabilityRequirements,
    OperationalMode,
    OperationalProperties,
    OperatingSystem,
    ToolCapabilityMetadata,
)
from wifi_framework.core.models.evidence import ConfidenceLevel, Evidence, EvidenceType
from wifi_framework.utils.validation import CONTROL_CHARS

#: The only operations a caller may request.
ALLOWED_OPERATIONS = ("version", "sniff")

#: Bounds on capture parameters, so a proposal cannot ask for an unbounded run.
MAX_COUNT = 10_000
MAX_TIMEOUT = 300
MAX_FILTER_LENGTH = 200

#: Parameters that carry code. Rejected unconditionally.
FORBIDDEN_PARAMETERS = ("script", "code", "source", "expr", "lambda")


class ScapyAdapter(ToolAdapterBase):
    """Runs a bounded set of Scapy operations with validated parameters."""

    def build_command(self, interface: str | None, parameters: Dict[str, Any]) -> List[str]:
        """Return a fixed probe command.

        This never embeds parameter data. The previous implementation returned
        ``["python3", "-c", <caller-supplied code>]``, which was a second
        arbitrary-execution path for whenever the in-process route was skipped.
        """
        return ["python3", "-c", "import scapy; print(scapy.__version__)"]

    def custom_requirement_check(
        self, interface: Optional[str], parameters: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """Scapy is a library, not a binary on PATH.

        ``requirements.dependencies`` is checked by looking for an executable, so
        a library listed there can never be satisfied - the capability reported
        itself unavailable even with Scapy installed. Detect it properly here.
        """
        parameters = parameters or {}

        # Input contract before environment probe. Whether Scapy happens to be
        # installed must not change which error a malformed request receives, or
        # the failure reason depends on the machine the suite runs on: with Scapy
        # absent, a sniff request with no interface used to report "Scapy library
        # is not importable" instead of the interface error, which made two tests
        # fail on any environment without the optional extra.
        operation = parameters.get("operation", "version")
        if operation == "sniff" and not interface:
            return False, "operation 'sniff' requires an interface"

        if find_spec("scapy") is None:
            return False, "Scapy library is not importable"
        return True, ""

    def custom_parameter_validation(self, parameters: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate the declarative parameter set. Previously returned (True, [])."""
        parameters = parameters or {}
        errors: List[str] = []

        for name in FORBIDDEN_PARAMETERS:
            if name in parameters:
                errors.append(
                    f"parameter '{name}' is rejected: this adapter does not execute "
                    f"caller-supplied code (choose an 'operation' instead)"
                )

        operation = parameters.get("operation", "version")
        if not isinstance(operation, str) or operation not in ALLOWED_OPERATIONS:
            errors.append(
                f"operation must be one of {ALLOWED_OPERATIONS}, got {operation!r}"
            )

        count = parameters.get("count", 100)
        if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= MAX_COUNT:
            errors.append(f"count must be an int in 1..{MAX_COUNT}, got {count!r}")

        capture_timeout = parameters.get("timeout", 10)
        if (
            not isinstance(capture_timeout, int)
            or isinstance(capture_timeout, bool)
            or not 1 <= capture_timeout <= MAX_TIMEOUT
        ):
            errors.append(f"timeout must be an int in 1..{MAX_TIMEOUT}, got {capture_timeout!r}")

        bpf = parameters.get("filter")
        if bpf is not None:
            if not isinstance(bpf, str):
                errors.append(f"filter must be a string, got {type(bpf).__name__}")
            elif len(bpf) > MAX_FILTER_LENGTH:
                errors.append(f"filter must be at most {MAX_FILTER_LENGTH} characters")
            elif any(ch in CONTROL_CHARS for ch in bpf):
                errors.append("filter must not contain control characters")

        return (not errors), errors

    def execute(
        self, interface: str | None = None, parameters: Dict[str, Any] = None, timeout: int = 30
    ) -> AdapterExecutionResult:
        parameters = dict(parameters or {})

        # Validate before touching Scapy, so a rejected request cannot produce
        # side effects. The previous version ran the payload first and reported
        # the failure afterwards.
        ok, errors = self.custom_parameter_validation(parameters)
        if not ok:
            return AdapterExecutionResult(
                success=False,
                raw_output="",
                error_output="; ".join(errors),
                exit_code=1,
                failure_reason=f"invalid_parameters: {'; '.join(errors)}",
                raw_command="scapy (rejected before execution)",
            )

        req_ok, req_reason = self.custom_requirement_check(interface, parameters)
        if not req_ok:
            return AdapterExecutionResult(
                success=False,
                raw_output="",
                error_output=req_reason,
                exit_code=1,
                failure_reason=f"Requirements not met: {req_reason}",
                raw_command="scapy (requirements unmet)",
            )

        # Import narrowly: only this statement may raise ImportError.
        try:
            import scapy.all as scapy
        except ImportError as exc:
            return AdapterExecutionResult(
                success=False,
                raw_output="",
                error_output=str(exc),
                exit_code=1,
                failure_reason=f"Scapy import failed: {exc}",
                raw_command="scapy (import failed)",
            )

        operation = parameters.get("operation", "version")
        try:
            if operation == "version":
                return self._version_result(scapy, parameters, interface)
            return self._sniff_result(scapy, parameters, interface)
        except Exception as exc:  # a capture failure is reported, not swallowed
            return AdapterExecutionResult(
                success=False,
                raw_output="",
                error_output=f"{type(exc).__name__}: {exc}",
                exit_code=1,
                failure_reason=f"scapy {operation} failed: {type(exc).__name__}: {exc}",
                raw_command=f"scapy {operation}",
            )

    def _version_result(self, scapy, parameters: Dict[str, Any], interface: str | None):
        # `scapy.all` does not re-export __version__; read the distribution so the
        # answer is the real version rather than "unknown".
        version = getattr(scapy, "__version__", None)
        if not version:
            try:
                from importlib.metadata import PackageNotFoundError, version as pkg_version

                version = pkg_version("scapy")
            except (ImportError, PackageNotFoundError):
                version = "unknown"
        evidence = Evidence.from_tool_output(
            tool_name="scapy",
            capability="protocol_analysis",
            evidence_type=EvidenceType.GENERIC,
            raw_output=version,
            parsed_data={"version": version, "operation": "version"},
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.HIGH,
            execution_id=self.execution_id,
            raw_command="scapy version",
        )
        return AdapterExecutionResult(
            success=True,
            raw_output=version,
            error_output="",
            exit_code=0,
            evidences=[evidence],
            raw_command="scapy version",
        )

    def _sniff_result(self, scapy, parameters: Dict[str, Any], interface: str | None):
        count = int(parameters.get("count", 100))
        capture_timeout = int(parameters.get("timeout", 10))
        bpf = parameters.get("filter")

        kwargs: Dict[str, Any] = {
            "iface": interface,
            "count": count,
            "timeout": capture_timeout,
            "store": True,
        }
        if bpf:
            kwargs["filter"] = bpf

        frames = scapy.sniff(**kwargs)

        # Summarise rather than serialise: the value is what was seen, and raw
        # frame dumps would put captured traffic into the evidence store.
        by_type: Dict[str, int] = {}
        for frame in frames:
            name = type(frame).__name__
            by_type[name] = by_type.get(name, 0) + 1
            for layer in getattr(frame, "layers", lambda: [])():
                layer_name = getattr(layer, "__name__", str(layer))
                by_type[layer_name] = by_type.get(layer_name, 0) + 1

        summary = {
            "operation": "sniff",
            "interface": interface,
            "frames_captured": len(frames),
            "requested_count": count,
            "timeout": capture_timeout,
            "filter": bpf,
            "frame_types": dict(sorted(by_type.items(), key=lambda kv: -kv[1])[:25]),
        }
        raw = "\n".join(f"{k}: {v}" for k, v in summary.items() if k != "frame_types")
        raw += "\nframe_types: " + ", ".join(f"{k}={v}" for k, v in summary["frame_types"].items())

        evidence = Evidence.from_tool_output(
            tool_name="scapy",
            capability="protocol_analysis",
            evidence_type=EvidenceType.CAPTURE,
            raw_output=raw,
            parsed_data=summary,
            parameters=parameters,
            interface=interface,
            confidence=ConfidenceLevel.HIGH,
            execution_id=self.execution_id,
            raw_command=f"scapy sniff iface={interface} count={count} timeout={capture_timeout}",
        )
        return AdapterExecutionResult(
            success=True,
            raw_output=raw,
            error_output="",
            exit_code=0,
            evidences=[evidence],
            raw_command=f"scapy sniff iface={interface} count={count} timeout={capture_timeout}",
        )

    def parse_output(
        self,
        raw_output: str,
        error_output: str,
        exit_code: int,
        parameters: Dict[str, Any],
        interface: str | None,
    ) -> List[Evidence]:
        if exit_code != 0 and not raw_output:
            return []

        return [
            Evidence.from_tool_output(
                tool_name="scapy",
                capability="protocol_analysis",
                evidence_type=EvidenceType.GENERIC,
                raw_output=raw_output,
                parsed_data={"output": raw_output[:2000], "interface": interface},
                parameters=parameters,
                interface=interface,
                confidence=ConfidenceLevel.MEDIUM,
                execution_id=self.execution_id,
                raw_command="scapy",
            )
        ]


METADATA = ToolCapabilityMetadata(
    name="scapy",
    display_name="Scapy - Packet Manipulation",
    category=CapabilityCategory.PROTOCOL_ANALYSIS,
    description=(
        "Programmable packet capture and analysis via the Scapy library. "
        "Bounded declarative operations only; caller-supplied code is rejected."
    ),
    tool_binary="python3",
    version="1.1",
    requirements=CapabilityRequirements(
        operating_systems=[OperatingSystem.LINUX],
        interface_required=False,
        privileges=[],
        # Scapy is a library, and `dependencies` is checked by looking for an
        # executable on PATH, so listing it there made the capability permanently
        # unavailable. custom_requirement_check() verifies importability instead.
        dependencies=[],
    ),
    inputs=[
        "optional_operation",
        "optional_count",
        "optional_timeout",
        "optional_filter",
        "optional_interface",
    ],
    outputs=["capture", "generic"],
    operational_properties=OperationalProperties(
        mode=OperationalMode.ACTIVE_TESTING,
        persistent=False,
        estimated_duration_seconds=10,
        invasive=True,
        requires_authorization=True,
    ),
    failure_conditions=["tool_not_found", "invalid_parameters"],
    tags=["packet", "scapy", "python"],
)

ADAPTER_CLASS = ScapyAdapter


def register(registry):
    registry.register(METADATA, ADAPTER_CLASS)
