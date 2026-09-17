"""
Execution gateway: the contract-facing half of the Execution Engine.

Specification section 5 requires an ``execution-result`` message with an enumerated status,
artifact references, tool and interface metadata, and a structured failure. It also states the
rule this module is most careful about:

    A failed execution must remain a failed execution. The Execution Engine must never convert
    a tool failure into an apparently successful result.

Execution is split into two stages so that the policy layer can validate concrete values before
anything runs (see ``docs/CONTRACT_LAYER_PLAN.md`` section 3):

``prepare()``  no side effects. Resolves the implementing tool, derives parameters from
               assessment state, selects the interface, and returns a *prepared* ActionRequest.
``run()``      invokes the real tool through the registered adapter, stores the output as
               artifacts, classifies the outcome, and emits the contract.

Status classification notes
---------------------------
* A capability that cannot run in this environment yields ``unsupported`` with no exit code -
  the tool was never invoked, and inventing an exit code would misrepresent that.
* A timeout that still produced parseable observations yields ``partial``, not ``failed``.
  This is the normal outcome for tools that observe until interrupted (``airodump-ng``,
  ``hcxdumptool``): the capture is real and usable, and the run genuinely did not complete.
  A timeout with nothing to show for it yields ``timeout``.
* Adapter-level parameter rejection yields ``rejected``; a non-zero exit yields ``failed``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ...contracts.action import ActionRequest, ActionValidationResult
from ...contracts.common import ArtifactRef, InterfaceRef, ToolRef
from ...contracts.envelope import EngineId, format_timestamp, utc_now
from ...contracts.execution import ExecutionFailure, ExecutionResult, ExecutionStatus, FailureCategory
from ..models.assessment_state import AssessmentState, ExecutionRecord
from ..models.evidence import Evidence
from .artifacts import (
    KIND_CSV,
    KIND_FILE,
    KIND_JSON,
    KIND_PCAP,
    KIND_STDERR,
    KIND_STDOUT,
    ArtifactStore,
)
from .executor import CapabilityExecutor
from ...utils.system import describe_unresolved, resolve_binary

#: Parameter names that may hold a path a tool wrote to.
_PATH_PARAMETER_KEYS = (
    "write_file",
    "output",
    "output_file",
    "capture_file",
    "pcap",
    "file",
    "path",
    "read_file",
    "input_file",
)

#: File extension -> artifact kind.
_KIND_BY_EXTENSION = {
    ".pcap": KIND_PCAP,
    ".cap": KIND_PCAP,
    ".pcapng": KIND_PCAP,
    ".csv": KIND_CSV,
    ".json": KIND_JSON,
}

#: Substrings in an adapter failure reason -> failure category.
_REASON_CATEGORIES: Tuple[Tuple[str, str], ...] = (
    ("not found in path", FailureCategory.TOOL_NOT_FOUND),
    ("tool_not_found", FailureCategory.TOOL_NOT_FOUND),
    # resolve_binary refuses a non-absolute name containing a separator, and an
    # absolute path that is not an executable file. Both mean "this binary cannot
    # be invoked", which is the same permanent refusal as a missing tool - no
    # amount of replanning fixes a malformed declaration.
    ("contains a path separator", FailureCategory.TOOL_NOT_FOUND),
    ("is not an executable file", FailureCategory.TOOL_NOT_FOUND),
    ("not available", FailureCategory.CAPABILITY_UNAVAILABLE),
    ("root privileges", FailureCategory.INSUFFICIENT_PRIVILEGES),
    ("must be root", FailureCategory.INSUFFICIENT_PRIVILEGES),
    ("permission denied", FailureCategory.PERMISSION_DENIED),
    ("insufficient_privileges", FailureCategory.INSUFFICIENT_PRIVILEGES),
    ("does not exist", FailureCategory.INTERFACE_UNAVAILABLE),
    ("no such device", FailureCategory.INTERFACE_UNAVAILABLE),
    ("interface_unavailable", FailureCategory.INTERFACE_UNAVAILABLE),
    ("unsupported_driver", FailureCategory.UNSUPPORTED_DRIVER),
    ("driver", FailureCategory.UNSUPPORTED_DRIVER),
    ("version insufficient", FailureCategory.TOOL_VERSION),
    ("dependency", FailureCategory.CAPABILITY_UNAVAILABLE),
    ("parameter validation", FailureCategory.INVALID_PARAMETERS),
    ("invalid_parameters", FailureCategory.INVALID_PARAMETERS),
    ("parsing failed", FailureCategory.PARSER_ERROR),
    ("command building failed", FailureCategory.INTERNAL_ERROR),
    ("execution exception", FailureCategory.INTERNAL_ERROR),
    ("timeout", FailureCategory.TIMEOUT),
    ("radio", FailureCategory.RADIO_BLOCKED),
)


@dataclass
class PreparedAction:
    """An ActionRequest resolved to a concrete tool, interface and parameter set."""

    request: ActionRequest
    metadata: Any
    interface: Optional[str]
    parameters: Dict[str, Any]
    timeout_seconds: int

    @property
    def implementation(self) -> str:
        return str(self.request.implementation or self.request.capability)


@dataclass
class ExecutionOutcome:
    """Everything the orchestrator needs from one attempted action."""

    result: ExecutionResult
    evidences: List[Evidence] = field(default_factory=list)
    record: Optional[ExecutionRecord] = None
    prepared: Optional[PreparedAction] = None
    validation: Optional[ActionValidationResult] = None

    @property
    def succeeded(self) -> bool:
        return self.result.succeeded

    def summary(self) -> Dict[str, Any]:
        return {
            "action_id": self.result.action_id,
            "execution_id": self.result.execution_id,
            "capability": self.result.capability,
            "implementation": self.result.implementation,
            "status": self.result.status,
            "exit_code": self.result.exit_code,
            "duration_ms": self.result.duration_ms,
            "evidences": len(self.evidences),
            "artifacts": [artifact.id for artifact in self.result.artifacts],
            "failure": self.result.failure.to_dict() if self.result.failure else None,
        }


def classify_failure(reason: Optional[str]) -> str:
    """Map an adapter's free-text failure reason onto a structured failure category."""
    if not reason:
        return FailureCategory.TOOL_ERROR
    lowered = reason.lower()
    for token, category in _REASON_CATEGORIES:
        if token in lowered:
            return category
    if lowered.startswith("tool_failed_exit_"):
        return FailureCategory.TOOL_ERROR
    return FailureCategory.TOOL_ERROR


def recorded_command(legacy: Any) -> List[str]:
    """The argument vector to record on an ``execution-result`` contract.

    ``contracts/execution.py`` promises that the recorded command "is exactly what
    was passed to ``subprocess.run`` and can be re-run by an auditor without
    reinterpretation". Reconstructing it from ``raw_command.split()`` breaks that
    promise for any argument containing whitespace - an SSID such as
    "Office Network" becomes two elements, and the recorded command can no longer
    be re-run.

    An adapter carrying ``argv`` is authoritative even when the list is empty:
    empty means no subprocess was launched. The Scapy adapter is exactly that case
    - it calls a library and stores a human-readable description such as
    "scapy sniff iface=wlan0" in ``raw_command``, which would otherwise split into
    an argv that was never executed and put a fabricated invocation in the audit
    trail. The ``.split()`` fallback exists only for results predating ``argv``.
    """
    if hasattr(legacy, "argv"):
        return list(legacy.argv)
    raw = getattr(legacy, "raw_command", "") or ""
    return raw.split() if raw else []


class ExecutionGateway:
    """Prepares and runs actions, emitting ``execution-result`` contracts."""

    def __init__(
        self,
        registry: Any,
        artifact_store: Optional[ArtifactStore] = None,
        *,
        executor: Optional[CapabilityExecutor] = None,
        tool_manager: Any = None,
        default_timeout: int = 60,
    ) -> None:
        self.registry = registry
        self.artifact_store = artifact_store
        self.tool_manager = tool_manager
        self.default_timeout = default_timeout
        self.executor = executor

    def _executor(self, state: Optional[AssessmentState]) -> CapabilityExecutor:
        if self.executor is not None:
            return self.executor
        return CapabilityExecutor(self.registry, state)

    # ------------------------------------------------------------------ prepare

    def prepare(
        self,
        request: ActionRequest,
        state: Optional[AssessmentState] = None,
        *,
        timeout: Optional[int] = None,
    ) -> Tuple[Optional[PreparedAction], Optional[ExecutionResult]]:
        """
        Resolve a request into a concrete invocation without running anything.

        Returns ``(prepared, None)`` on success or ``(None, result)`` when the request cannot be
        prepared, in which case the result already carries an honest ``unsupported`` status.
        """
        implementation = request.implementation or request.capability
        metadata = self.registry.get_metadata(implementation)
        if metadata is None:
            return None, self._refuse(
                request,
                status=ExecutionStatus.UNSUPPORTED,
                category=FailureCategory.CAPABILITY_UNAVAILABLE,
                message=f"capability '{implementation}' is not registered",
                implementation=implementation,
            )
        if self.registry.get_adapter_class(implementation) is None:
            return None, self._refuse(
                request,
                status=ExecutionStatus.UNSUPPORTED,
                category=FailureCategory.CAPABILITY_UNAVAILABLE,
                message=f"capability '{implementation}' has no adapter implementation",
                implementation=implementation,
                metadata=metadata,
            )

        # Attribute the refusal to the most fundamental blocker. A tool that is not installed
        # cannot run whatever interface happens to be selected, so reporting "interface
        # unavailable" here would send the operator after the wrong problem - and would make the
        # refusal look retriable when no amount of replanning can fix a missing binary. This is a
        # PATH scan, not the version probe ``check_tool_available`` performs.
        if resolve_binary(metadata.tool_binary) is None:
            return None, self._refuse(
                request,
                status=ExecutionStatus.UNSUPPORTED,
                category=FailureCategory.TOOL_NOT_FOUND,
                message=describe_unresolved(metadata.tool_binary),
                implementation=implementation,
                metadata=metadata,
            )

        executor = self._executor(state)
        hints = dict(request.parameters or {})
        parameters: Dict[str, Any] = {}
        if state is not None:
            generated = executor.generate_parameters_from_state(implementation, state, hints)
            # Explicit decision hints win over values derived from state, matching the
            # pre-0.4.0 executor semantics.
            parameters = {**generated, **hints}
        else:
            parameters = dict(hints)

        interface = request.interface or parameters.get("interface")
        if metadata.requirements.interface_required and not interface:
            return None, self._refuse(
                request,
                status=ExecutionStatus.UNSUPPORTED,
                category=FailureCategory.INTERFACE_UNAVAILABLE,
                message=f"'{implementation}' requires an interface and none could be derived from state",
                implementation=implementation,
                metadata=metadata,
            )

        effective_timeout = int(timeout or request.timeout_seconds or self.default_timeout)
        prepared_request = request.with_parameters(
            parameters, interface=interface, implementation=implementation
        )
        return (
            PreparedAction(
                request=prepared_request,
                metadata=metadata,
                interface=interface,
                parameters=parameters,
                timeout_seconds=effective_timeout,
            ),
            None,
        )

    # ---------------------------------------------------------------------- run

    def run(
        self,
        prepared: PreparedAction,
        state: Optional[AssessmentState] = None,
        *,
        validation: Optional[ActionValidationResult] = None,
    ) -> ExecutionOutcome:
        """Invoke the real tool and report the outcome as an ``execution-result`` contract."""
        request = prepared.request
        metadata = prepared.metadata
        implementation = prepared.implementation
        executor = self._executor(state)
        started_at = utc_now()

        legacy = executor.execute(
            capability_name=implementation,
            interface=prepared.interface,
            parameters=dict(prepared.parameters),
            timeout=prepared.timeout_seconds,
            state=state,
            record_state=False,
        )
        completed_at = utc_now()

        artifacts, stdout_artifact, stderr_artifact, storage_warnings = self._store_artifacts(
            legacy, prepared, execution_id=legacy.execution_id
        )
        status, failure, warnings = self._classify(legacy, artifacts)
        warnings.extend(storage_warnings)
        tool_ref = self._tool_ref(metadata, implementation)
        interface_ref = self._interface_ref(prepared.interface, state)
        duration_ms = int(round((legacy.duration or 0.0) * 1000))
        # Prefer the argument vector the adapter actually passed to subprocess.
        # `raw_command.split()` cannot reconstruct it: an argument containing a
        # space becomes two elements, so the recorded command would not be the
        # command that ran. The fallback covers results built before argv existed.
        command = recorded_command(legacy)

        result = ExecutionResult(
            assessment_id=request.assessment_id,
            source_engine=EngineId.EXECUTION.value,
            correlation_id=request.correlation_id,
            action_id=request.action_id,
            execution_id=legacy.execution_id or "",
            status=status,
            capability=request.capability,
            implementation=implementation,
            started_at=format_timestamp(started_at),
            completed_at=format_timestamp(completed_at),
            duration_ms=duration_ms,
            exit_code=legacy.exit_code if legacy.raw_command else None,
            stdout_artifact=stdout_artifact,
            stderr_artifact=stderr_artifact,
            artifacts=artifacts,
            tool=tool_ref,
            interface=interface_ref,
            failure=failure,
            command=command,
            # Extraction problems travel on their own field so the Evidence Engine can
            # fold them into parse_issues without treating every warning as one.
            parse_warnings=list(getattr(legacy, "parse_warnings", None) or []),
            parameters=dict(prepared.parameters),
            warnings=warnings,
            scope_authorised=bool(validation.approved) if validation is not None else False,
        )

        record = ExecutionRecord(
            id=result.execution_id,
            timestamp=started_at,
            capability_name=implementation,
            tool_binary=metadata.tool_binary,
            interface=prepared.interface,
            parameters=dict(prepared.parameters),
            raw_command=legacy.raw_command or "",
            exit_code=result.exit_code,
            duration_seconds=legacy.duration or 0.0,
            success=result.succeeded,
            evidence_ids=[evidence.id for evidence in legacy.evidences],
            failure_reason=legacy.failure_reason or (failure.message if failure else None),
            information_gain=float(len(legacy.evidences)),
            cost=legacy.duration or 0.0,
            action_id=request.action_id,
            correlation_id=request.correlation_id,
            status=status,
            artifact_ids=[artifact.id for artifact in artifacts],
        )
        return ExecutionOutcome(
            result=result,
            evidences=list(legacy.evidences),
            record=record,
            prepared=prepared,
            validation=validation,
        )

    # ------------------------------------------------------------------ refusing

    def _refuse(
        self,
        request: ActionRequest,
        *,
        status: str,
        category: str,
        message: str,
        implementation: Optional[str] = None,
        metadata: Any = None,
    ) -> ExecutionResult:
        """
        Build an honest result for an action that was never attempted.

        ``exit_code`` stays ``None``: the tool did not run, and the contract's semantic
        validation rejects a not-executed status that claims an exit code.
        """
        now = format_timestamp(utc_now())
        return ExecutionResult(
            assessment_id=request.assessment_id,
            source_engine=EngineId.EXECUTION.value,
            correlation_id=request.correlation_id,
            action_id=request.action_id,
            execution_id=f"execution-{request.action_id[:12]}",
            status=status,
            capability=request.capability,
            implementation=implementation or request.implementation,
            started_at=now,
            completed_at=now,
            duration_ms=0,
            exit_code=None,
            tool=ToolRef(name=metadata.tool_binary) if metadata is not None else None,
            interface=InterfaceRef(name=request.interface) if request.interface else None,
            failure=ExecutionFailure(
                code=category,
                category=category,
                message=message,
                retriable=category in FailureCategory.RETRIABLE,
                details={"capability": request.capability, "implementation": implementation},
            ),
            parameters=dict(request.parameters or {}),
        )

    # ------------------------------------------------------------------ artifacts

    def _store_artifacts(
        self, legacy: Any, prepared: PreparedAction, *, execution_id: str
    ) -> Tuple[List[ArtifactRef], Optional[str], Optional[str], List[str]]:
        """Store the run's streams and any files the tool wrote.

        The fourth element carries warnings about the storage itself - currently,
        artifacts whose permissions could not be restricted to the owner. They are
        advisories rather than failures: the bytes were written and hashed correctly,
        but a captured handshake left readable by other local users is worth putting in
        the audit trail rather than only in a statistics dict.
        """
        artifacts: List[ArtifactRef] = []
        storage_warnings: List[str] = []
        stdout_id = stderr_id = None
        if self.artifact_store is not None:
            before = len(self.artifact_store.permission_failures)
            stdout = self.artifact_store.store_text(
                KIND_STDOUT, legacy.raw_output or "", description="tool stdout", execution_id=execution_id
            )
            if stdout is not None:
                artifacts.append(stdout)
                stdout_id = stdout.id
            stderr = self.artifact_store.store_text(
                KIND_STDERR, legacy.error_output or "", description="tool stderr", execution_id=execution_id
            )
            if stderr is not None:
                artifacts.append(stderr)
                stderr_id = stderr.id
            artifacts.extend(self._register_output_files(prepared.parameters, execution_id))
            for path in self.artifact_store.permission_failures[before:]:
                storage_warnings.append(
                    f"artifact {path} could not be restricted to owner-only access and may be "
                    "readable by other local users"
                )
        return artifacts, stdout_id, stderr_id, storage_warnings

    def _register_output_files(self, parameters: Dict[str, Any], execution_id: str) -> List[ArtifactRef]:
        """
        Register files the tool wrote, when they still exist.

        Adapters that manage their own temporary captures may already have consumed and removed
        the file; registering only what exists keeps the artifact list truthful.
        """
        registered: List[ArtifactRef] = []
        if self.artifact_store is None:
            return registered
        for key in _PATH_PARAMETER_KEYS:
            value = parameters.get(key)
            if not isinstance(value, str) or not value:
                continue
            if not os.path.isfile(value):
                continue
            extension = os.path.splitext(value)[1].lower()
            artifact = self.artifact_store.register_file(
                value,
                _KIND_BY_EXTENSION.get(extension, KIND_FILE),
                description=f"{key}={os.path.basename(value)}",
                execution_id=execution_id,
            )
            if artifact is not None:
                registered.append(artifact)
        return registered

    # --------------------------------------------------------------- classifying

    @staticmethod
    def _classify(legacy: Any, artifacts: List[ArtifactRef]) -> Tuple[str, Optional[ExecutionFailure], List[str]]:
        warnings: List[str] = []
        reason = legacy.failure_reason
        executed = bool(legacy.raw_command)

        if not executed:
            category = classify_failure(reason)
            status = (
                ExecutionStatus.REJECTED
                if category in (FailureCategory.INVALID_PARAMETERS,)
                else ExecutionStatus.UNSUPPORTED
            )
            return (
                status,
                ExecutionFailure(
                    code=category,
                    category=category,
                    message=reason or "the tool was never invoked",
                    retriable=category in FailureCategory.RETRIABLE,
                    details={"exit_code": legacy.exit_code},
                ),
                warnings,
            )

        if legacy.success:
            if any(artifact.truncated for artifact in artifacts):
                warnings.append("one or more artifacts exceeded the size cap and were truncated")
            return ExecutionStatus.SUCCESS, None, warnings

        if legacy.exit_code == 124:
            observations = len(legacy.evidences or [])
            if observations:
                # Interrupted observation tools still produced real, usable evidence.
                warnings.append(
                    f"run was stopped by the timeout after producing {observations} observation(s)"
                )
                return (
                    ExecutionStatus.PARTIAL,
                    ExecutionFailure(
                        code=FailureCategory.TIMEOUT,
                        category=FailureCategory.TIMEOUT,
                        message=(
                            f"execution stopped at the timeout after producing {observations} "
                            "observation(s); the run did not complete"
                        ),
                        retriable=True,
                        details={"observations": observations},
                    ),
                    warnings,
                )
            return (
                ExecutionStatus.TIMEOUT,
                ExecutionFailure(
                    code=FailureCategory.TIMEOUT,
                    category=FailureCategory.TIMEOUT,
                    message=reason or "execution exceeded its timeout and produced no observations",
                    retriable=True,
                    details={"exit_code": legacy.exit_code},
                ),
                warnings,
            )

        category = classify_failure(reason)
        return (
            ExecutionStatus.FAILED,
            ExecutionFailure(
                code=category,
                category=category,
                message=reason or f"tool exited with code {legacy.exit_code}",
                retriable=category in FailureCategory.RETRIABLE,
                details={"exit_code": legacy.exit_code},
            ),
            warnings,
        )

    def _tool_ref(self, metadata: Any, implementation: str) -> ToolRef:
        version: Optional[str] = None
        path: Optional[str] = None
        probe_error: Optional[str] = None
        if self.tool_manager is not None:
            try:
                info = self.tool_manager.check_tool_deep(metadata.tool_binary)
                version = info.version_raw
                path = info.path
            except Exception as exc:
                # Tool metadata is descriptive; a probe failure must not abort the execution.
                version = None
                probe_error = f"{type(exc).__name__}: {exc}"
        if path is None:
            # The probe is cached and best-effort. ``ToolRef.path`` is what the audit
            # trail records as the binary that ran, so an unknown path here would
            # leave the record silent on exactly the field the resolver exists to pin
            # down. Resolve directly rather than publish ``path: null``.
            path = resolve_binary(metadata.tool_binary)
        return ToolRef(
            name=metadata.tool_binary,
            version=version,
            path=path,
            adapter=implementation,
            adapter_version=str(getattr(metadata, "version", "1.0")),
        )

    def _interface_ref(self, interface: Optional[str], state: Optional[AssessmentState]) -> Optional[InterfaceRef]:
        if not interface:
            return None
        info = state.interfaces.get(interface) if state is not None else None
        if info is None:
            return InterfaceRef(name=interface)
        capabilities: List[str] = []
        if info.supports_monitor:
            capabilities.append("monitor_mode")
        if info.supports_injection:
            capabilities.append("packet_injection")
        return InterfaceRef(
            name=interface,
            driver=info.driver,
            chipset=info.chipset,
            mac=info.mac,
            is_up=bool(info.is_up),
            capabilities=capabilities,
        )
