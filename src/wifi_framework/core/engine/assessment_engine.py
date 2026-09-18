"""
Assessment engine - main orchestrator.

Implements iterative observation-and-decision loop:
Observe → Model → Identify uncertainty → Select action → Parameterize → Execute → Parse → Verify → Update → Re-evaluate

A previously used tool may be selected again if new evidence makes it useful.
Conversely, a tool may be skipped entirely when required information has already
been established through another observation.
"""
from __future__ import annotations

import os
import uuid
from typing import Any, Dict, List, Optional, Union

from ...contracts.action import ActionObjective, ActionOrigin, ActionReason, ActionRequest
from ...contracts.common import EntityRef, TargetType
from ...contracts.envelope import EngineId
from ...contracts.execution import ExecutionFailure, ExecutionResult as ExecutionResultContract
from ...contracts.execution import ExecutionStatus, FailureCategory
from ...contracts.verification import VerificationRequest, VerificationStatus
from ...contracts.world_state import WorldState
from ..models.assessment_state import AssessmentState, AssessmentPhase, ExecutionRecord, InterfaceInfo
from ..models.scope import AssessmentScope, ScopeEnforcer
from ..models.finding import Finding, FindingCategory, FindingSeverity, FindingStatus
from ..models.evidence import EvidenceType
from ..models.wpa3 import Wpa3Posture, assess_dragonblood_exposure
from ..execution.registry import CapabilityRegistry, get_global_registry
from ..execution.executor import CapabilityExecutor
from ..execution.tool_manager import ToolManager
from ..execution.interface_manager import InterfaceManager
from ..execution.dependency_resolver import DependencyResolver
from ..execution.artifacts import ArtifactStore
from ..execution.gateway import ExecutionGateway, ExecutionOutcome
from ..decision.engine import DecisionEngine
from ..policy.validator import ActionPolicy
from ..evidence.engine import EvidenceEngine
from ..verification.engine import VerificationEngine, VerificationOutcome
from ..world.applier import WorldModelApplier
from ..world.state_publisher import WorldStatePublisher, uncertainty_id
from ..experience.engine import ExperienceEngine
from ..planning.planner import AssessmentPlanner
from ..audit.logger import AuditLogger
from ..experience.store import ExperienceStore
from ...utils.system import get_interface_list
from ...tools.registry_loader import load_all_adapters

#: How often (in loop iterations) open findings are re-examined by the Verification Engine.
DEFAULT_VERIFY_EVERY = 5
#: Default freshness window for observations, in seconds.
DEFAULT_STALENESS_SECONDS = 600
#: Iterations a transient (retriable) policy refusal suppresses a capability before it may be
#: requested again. Permanent refusals - scope denial, unknown capability, unsafe parameters -
#: are never retried, because no change of circumstance can make them acceptable.
BLOCK_COOLDOWN_ITERATIONS = 3

#: Failure categories that cannot be resolved by continuing the assessment: the tool is absent,
#: too old, or its driver cannot do what was asked. These suppress the capability permanently.
#: Everything else (a missing target, a down interface, a timeout) is suppressed only for
#: ``BLOCK_COOLDOWN_ITERATIONS``, because later evidence can make the action viable.
_PERMANENT_BLOCK_CATEGORIES = {
    FailureCategory.TOOL_NOT_FOUND,
    FailureCategory.CAPABILITY_UNAVAILABLE,
    FailureCategory.TOOL_VERSION,
    FailureCategory.UNSUPPORTED_DRIVER,
    FailureCategory.SCOPE_DENIED,
}


class AssessmentEngine:
    """
    Main assessment engine.

    Adaptive, state-driven, capability-aware, auditable.
    """

    def __init__(
        self,
        scope: AssessmentScope,
        registry: Optional[CapabilityRegistry] = None,
        audit_logger: Optional[AuditLogger] = None,
        experience_store: Optional[ExperienceStore] = None,
        assessment_state: Optional[AssessmentState] = None,
        artifact_dir: Optional[str] = None,
        staleness_seconds: int = DEFAULT_STALENESS_SECONDS,
        max_verification_attempts: int = 2,
    ):
        self.scope = scope
        self.scope_enforcer = ScopeEnforcer(scope)

        # Registry
        if registry is None:
            registry = get_global_registry()
            load_all_adapters(registry)
        self.registry = registry

        # State
        if assessment_state is None:
            self.state = AssessmentState(scope=scope)
        else:
            self.state = assessment_state

        # Tool Manager - advanced handling
        self.tool_manager = ToolManager(registry)
        self.interface_manager = InterfaceManager(self.tool_manager)
        self.dependency_resolver = DependencyResolver(registry)

        # Executor
        self.executor = CapabilityExecutor(registry, self.state)

        # Planner
        self.planner = AssessmentPlanner(registry)

        # Audit
        if audit_logger is None:
            audit_logger = AuditLogger(assessment_id=self.state.id)
        self.audit_logger = audit_logger
        self.audit_logger.log_scope(scope)

        # Experience
        if experience_store is None:
            experience_store = ExperienceStore()
        self.experience_store = experience_store

        # Load experience scores into state for planner
        self.state.extra["experience_scores"] = self.experience_store.get_experience_scores()
        self.state.extra["tool_manager"] = self.tool_manager.to_dict()

        # --- contract subsystems (0.4.0) ------------------------------------
        # Each subsystem communicates only through the published contracts in
        # ``wifi_framework.contracts``. The orchestrator routes messages between them; it owns
        # none of them and contains no assessment logic of its own.
        self.staleness_seconds = staleness_seconds
        self.max_verification_attempts = max(1, int(max_verification_attempts))
        self.world_publisher = WorldStatePublisher(staleness_seconds=staleness_seconds)
        self.applier = WorldModelApplier()
        self.decision_engine = DecisionEngine(registry)
        self.policy = ActionPolicy(registry, scope)
        self.artifact_store = ArtifactStore(
            base_dir=artifact_dir or os.path.join(self.audit_logger.log_dir, "artifacts", self.state.id),
            assessment_id=self.state.id,
        )
        self.execution_gateway = ExecutionGateway(
            registry,
            self.artifact_store,
            executor=self.executor,
            tool_manager=self.tool_manager,
            default_timeout=60,
        )
        self.evidence_engine = EvidenceEngine(scope, max_age_seconds=staleness_seconds)
        self.verification_engine = VerificationEngine(default_max_age_seconds=staleness_seconds)
        self.experience_engine = ExperienceEngine(self.experience_store)

        # Routing state for the verification loop.
        self._iteration = 0
        self._world_state_cache: Optional[WorldState] = None
        self._pending_verification_requests: List[VerificationRequest] = []
        self._pending_verification_actions: List[ActionRequest] = []
        self._verification_attempts: Dict[str, int] = {}
        #: Capabilities the policy layer refused or deferred, with the reason. Prevents the
        #: loop from re-requesting an action that cannot succeed in this environment.
        self._blocked_capabilities: Dict[str, Dict[str, Any]] = {}
        self.state.extra["blocked_capabilities"] = self._blocked_capabilities
        self.state.extra.setdefault("verifications", [])

    def discover_interfaces(self) -> List[InterfaceInfo]:
        """Discover wireless interfaces using iw and iwconfig with deep capability checks."""
        print("[*] Discovering wireless interfaces with deep capability checks...")

        # Use ToolManager for deep discovery
        deep_interfaces = self.tool_manager.discover_all_interfaces()
        print(f"    Deep scan found {len(deep_interfaces)} interfaces with driver/monitor/injection checks")

        # Bootstrap observations run through the same contract pipeline as planned actions, so
        # every execution in the history carries an action id and can be traced.
        for capability_name, timeout, label in (
            ("iw_dev", 10, "interface observations via iw"),
            ("iwconfig", 10, "interface observations via iwconfig"),
            ("rfkill", 5, "radio block states via rfkill"),
        ):
            outcome = self.run_discovery_action(capability_name, timeout=timeout)
            if outcome is None:
                continue
            if outcome.result.succeeded:
                print(f"    Found {len(outcome.evidences)} {label}")
            else:
                failure = outcome.result.failure
                detail = failure.message if failure else ""
                print(f"    {capability_name}: {outcome.result.status}" + (f" - {detail}" if detail else ""))

        # Build InterfaceInfo from evidences and deep checks
        interfaces = {}

        # Get system interfaces
        sys_ifaces = get_interface_list()
        for iface_name in sys_ifaces:
            # Skip loopback
            if iface_name == "lo":
                continue

            # Use deep check if available
            if iface_name in deep_interfaces:
                deep_cap = deep_interfaces[iface_name]
                info = InterfaceInfo(
                    name=deep_cap.name,
                    type=deep_cap.type,
                    driver=deep_cap.driver,
                    chipset=deep_cap.chipset,
                    mac=deep_cap.mac,
                    supports_monitor=deep_cap.supports_monitor,
                    supports_injection=deep_cap.supports_injection,
                    is_up=deep_cap.is_up,
                    channel=deep_cap.current_channel,
                    extra={
                        "monitor_tested": deep_cap.monitor_tested,
                        "injection_tested": deep_cap.injection_tested,
                        "injection_result": deep_cap.injection_test_result,
                        "channels": deep_cap.channels,
                        "deep_discovery": True,
                    },
                )
            else:
                # Check if we have evidence for this interface
                info = InterfaceInfo(name=iface_name, type="unknown")

                # Look for evidence
                for ev in self.state.evidences:
                    if ev.evidence_type == EvidenceType.INTERFACE:
                        if ev.parsed_data.get("name") == iface_name:
                            info.type = ev.parsed_data.get("type", info.type)
                            info.mac = ev.parsed_data.get("mac") or ev.parsed_data.get("addr")
                            info.driver = ev.parsed_data.get("driver")
                            info.channel = ev.parsed_data.get("channel")
                            info.frequency = ev.parsed_data.get("frequency")
                            # Check for monitor support from iw list if available
                            if ev.parsed_data.get("supports_monitor"):
                                info.supports_monitor = True

            interfaces[iface_name] = info

        # Also parse evidences that have interface names not in sys list (like mon interfaces)
        for ev in self.state.evidences:
            if ev.evidence_type == EvidenceType.INTERFACE:
                name = ev.parsed_data.get("name")
                if name and name not in interfaces:
                    info = InterfaceInfo(name=name, type=ev.parsed_data.get("type", "unknown"))
                    info.mac = ev.parsed_data.get("mac")
                    interfaces[name] = info

        self.state.interfaces = interfaces

        print(f"[+] Discovered {len(interfaces)} interfaces: {list(interfaces.keys())}")
        for name, info in interfaces.items():
            print(f"    - {name}: type={info.type} driver={info.driver} monitor={info.supports_monitor} injection={info.supports_injection} up={info.is_up}")

        return list(interfaces.values())

    def discover_capabilities(self, interface: Optional[str] = None):
        """Discover available capabilities in current environment with deep checks."""
        print("[*] Discovering tool capabilities with deep management...")

        # Use ToolManager for deep tool discovery
        deep_tools = self.tool_manager.discover_all_tools()
        print(f"    Deep tool scan: {len(deep_tools)} binaries checked")

        available = {}
        unavailable = {}

        # Deep check each capability
        for cap_name in self.registry.list_capabilities():
            ok, reason, details = self.tool_manager.get_capability_status(cap_name, interface)
            meta = self.registry.get_metadata(cap_name)
            if ok:
                available[cap_name] = meta
            else:
                unavailable[cap_name] = reason

        self.state.available_capabilities = available
        self.state.unavailable_capabilities = unavailable

        self.audit_logger.log_capability_discovery(available, unavailable)

        # Log tool manager state
        self.audit_logger.log_event("tool_manager_state", self.tool_manager.to_dict())
        self.audit_logger.log_event("dependency_resolver", self.dependency_resolver.to_dict())

        print(f"[+] Available capabilities: {len(available)}")
        print(f"    Unavailable: {len(unavailable)}")
        for name, reason in list(unavailable.items())[:8]:
            print(f"      - {name}: {reason}")
        if len(unavailable) > 8:
            print(f"      ... and {len(unavailable)-8} more")

        # Show tool chains feasibility
        for objective in ["handshake_capture", "wps_assessment", "network_discovery", "vulnerability_assessment"]:
            chain = self.tool_manager.get_tool_chain(objective)
            feasible, missing, reasons = self.dependency_resolver.check_tool_chain_feasibility(chain, interface)
            status = "FEASIBLE" if feasible else f"PARTIAL (missing: {missing})"
            print(f"    Chain {objective}: {status}")

        return available, unavailable

    # ------------------------------------------------------------ action pipeline

    def run_discovery_action(
        self,
        capability_name: str,
        *,
        objective: str = ActionObjective.DISCOVER_INTERFACES,
        timeout: int = 30,
        interface: Optional[str] = None,
    ) -> Optional[ExecutionOutcome]:
        """
        Run an environment-bootstrap capability through the contract pipeline.

        Interface and capability discovery happen before any WorldState exists, but they are
        still real operations against real tools, so they are expressed as an ``action-request``
        with an explicit bootstrap objective. This keeps one execution route through the
        framework: discovery actions are policy-validated, artifact-recorded and audited exactly
        like planned actions, and a tool that is not installed yields ``unsupported`` rather than
        a failed-looking execution.
        """
        metadata = self.registry.get_metadata(capability_name)
        if metadata is None:
            print(f"    {capability_name}: capability is not registered")
            return None
        category = metadata.category.value if hasattr(metadata.category, "value") else str(metadata.category)
        request = ActionRequest(
            assessment_id=self.state.id,
            source_engine=EngineId.ORCHESTRATOR.value,
            correlation_id=self.state.id,
            action_id=str(uuid.uuid4()),
            capability=category,
            objective=objective,
            target=EntityRef(type=TargetType.INTERFACE.value, id=interface),
            prerequisites=[f"tool:{metadata.tool_binary}"],
            expected_outputs=list(metadata.outputs or []),
            reason=ActionReason(summary=f"environment bootstrap: {capability_name}"),
            implementation=capability_name,
            interface=interface,
            origin=ActionOrigin.OPERATOR,
            timeout_seconds=timeout,
        )
        return self.execute_action_request(request, timeout=timeout)

    def run_single_action(
        self, action: Union[Dict[str, Any], ActionRequest], timeout: int = 60
    ) -> bool:
        """
        Execute one planned action through the contract pipeline.

        Accepts either a legacy action dict (the v0.1.0-v0.3.0 planner output) or an
        ``action-request`` contract, so existing callers keep working. Scope enforcement,
        capability validation and parameter validation are performed by the policy layer rather
        than inline here, which is why the legacy and contract paths cannot drift apart.

        Returns True only when the real tool ran and reported success.
        """
        request = action if isinstance(action, ActionRequest) else self.legacy_action_to_request(action)
        outcome = self.execute_action_request(request, timeout=timeout)
        return bool(outcome is not None and outcome.result.succeeded)

    def legacy_action_to_request(self, action: Dict[str, Any]) -> ActionRequest:
        """
        Convert a pre-0.4.0 planner action dict into an ``action-request`` contract.

        Kept so that ``AssessmentPlanner`` output, and any external caller using it, continues
        to work through the same validated pipeline.
        """
        metadata = action.get("capability_metadata") or self.registry.get_metadata(
            action.get("capability_name", "")
        )
        uncertainty: Dict[str, Any] = dict(action.get("uncertainty") or {})
        implementation = action.get("capability_name") or ""
        capability = "unknown"
        if metadata is not None:
            capability = (
                metadata.category.value if hasattr(metadata.category, "value") else str(metadata.category)
            )
        subjects: List[str] = []
        context = uncertainty.get("context") or {}
        for key in ("bssids", "finding_ids", "ips", "interfaces", "macs"):
            value = context.get(key)
            if isinstance(value, list):
                subjects.extend(str(item) for item in value)
        gap_id = uncertainty_id(str(uncertainty.get("type") or ""), subjects) if uncertainty else None
        target = EntityRef(type=TargetType.NONE.value)
        if subjects:
            target = EntityRef(
                type=TargetType.ACCESS_POINT.value if ":" in subjects[0] else TargetType.HOST.value,
                id=subjects[0],
            )
        return ActionRequest(
            assessment_id=self.state.id,
            source_engine=EngineId.DECISION.value,
            correlation_id=self.state.id,
            action_id=str(uuid.uuid4()),
            capability=capability,
            objective=ActionObjective.RESOLVE_INFORMATION_GAP,
            target=target,
            parameters=dict(action.get("parameters") or {}),
            expected_outputs=list(metadata.outputs or []) if metadata is not None else [],
            verification_required=bool(
                metadata is not None and metadata.operational_properties.invasive
            ),
            reason=ActionReason(
                information_gaps=[gap_id] if gap_id else [],
                summary=str(action.get("reason") or ""),
                uncertainty_type=str(uncertainty.get("type") or "") or None,
                score=action.get("score"),
            ),
            implementation=implementation,
            interface=action.get("interface"),
            origin=ActionOrigin.PLANNER,
            priority=int(uncertainty.get("priority") or 0),
        )

    def execute_action_request(
        self,
        request: ActionRequest,
        *,
        timeout: Optional[int] = None,
        world_state: Optional[WorldState] = None,
    ) -> Optional[ExecutionOutcome]:
        """
        Run the full contract pipeline for one action request.

            prepare -> validate -> execute -> evidence -> world model -> verify -> experience

        Every stage produces a contract that is audited. A refusal at any stage is recorded as
        an honest non-execution result; it is never represented as a success.
        """
        published = world_state or self.publish_world_state()
        state_before = published.digest()

        print(
            f"[*] Executing: {request.implementation or request.capability} "
            f"(interface={request.interface}) - {request.reason.summary}"
        )

        # 1. prepare (no side effects) ---------------------------------------
        prepared, refusal = self.execution_gateway.prepare(request, self.state, timeout=timeout)
        if prepared is None or refusal is not None:
            assert refusal is not None  # prepare returns exactly one of the two
            self.block_capability(request, stage="prepare", reason=refusal.failure.message if refusal.failure else "unavailable", permanent=not (refusal.failure and refusal.failure.retriable))
            return self.record_refused(request, refusal, state_before=state_before)

        # 2. policy validation ----------------------------------------------
        validation = self.policy.validate(prepared.request, self.state)
        self.audit_logger.log_contract(validation)
        if not validation.approved:
            rejection = validation.rejection or {}
            print(f"[!] Policy {validation.status}: {rejection.get('reason', 'rejected')}")
            self.audit_logger.log_contract_rejection(
                prepared.request.action_id, rejection, str(rejection.get("stage", "policy"))
            )
            self.block_capability(
                prepared.request,
                stage=str(rejection.get("stage", "policy")),
                reason=str(rejection.get("reason", validation.status)),
                permanent=not bool(rejection.get("retriable", False)),
            )
            refused = self.rejection_result(prepared.request, validation)
            return self.record_refused(
                prepared.request, refused, validation=validation, state_before=state_before
            )

        # 3. real execution --------------------------------------------------
        self.audit_logger.log_contract(prepared.request)
        outcome = self.execution_gateway.run(prepared, self.state, validation=validation)
        self.audit_logger.log_contract(outcome.result)

        # An action the tool layer refused without ever running is environmental information:
        # suppress the capability so the Decision Engine replans instead of re-requesting it.
        if outcome.result.status in ExecutionStatus.TERMINAL_NOT_EXECUTED:
            category = outcome.result.failure.category if outcome.result.failure else ""
            self.block_capability(
                prepared.request,
                stage="execution",
                reason=outcome.result.failure.message if outcome.result.failure else outcome.result.status,
                permanent=category in _PERMANENT_BLOCK_CATEGORIES,
            )

        if outcome.record is not None:
            self.applier.apply_execution(self.state, outcome.record)
            self.audit_logger.log_execution(outcome.record)
        self.invalidate_world_state()

        # 4. evidence -------------------------------------------------------
        processing = self.evidence_engine.process(
            outcome.result,
            outcome.evidences,
            action_id=request.action_id,
            capability=request.capability,
        )
        apply_report = self.applier.apply_evidence(self.state, processing.evidence_set, processing.evidences)
        self.audit_logger.log_contract(processing.evidence_set, summary=processing.summary())
        for evidence in processing.evidences:
            self.audit_logger.log_evidence(evidence)
        self.invalidate_world_state()
        for verification_request in processing.verification_requests:
            self.queue_verification_request(verification_request)

        # 5. verification (only when the action asked for it) ---------------
        verification_result = None
        if request.verification_required and processing.verification_requests:
            outcomes = self.run_verification_cycle()
            for candidate in outcomes:
                if candidate.result.action_id == request.action_id:
                    verification_result = candidate.result
                    break
            if verification_result is None and outcomes:
                verification_result = outcomes[0].result

        # 6. experience ----------------------------------------------------
        world_after = self.publish_world_state(force=True)
        gaps_closed = self.closed_gaps(published, world_after)
        required_root = bool(
            prepared.metadata is not None and "root" in prepared.metadata.requirements.privileges
        )
        experience = self.experience_engine.record(
            prepared.request,
            outcome.result,
            evidence_set=processing.evidence_set,
            verification=verification_result,
            state_before=state_before,
            state_after=world_after.digest(),
            state_revision=world_after.revision,
            new_observations=apply_report.accepted,
            gaps_closed=gaps_closed,
            required_root=required_root,
        )
        self.audit_logger.log_contract(
            experience.record,
            summary={
                "information_gain": experience.information_gain,
                "useful": experience.useful,
                "new_observations": experience.new_observations,
                "gaps_closed": experience.gaps_closed,
                "state_changed": experience.record.state_changed,
            },
        )
        self.state.extra["experience_scores"] = self.experience_store.get_experience_scores()
        self.invalidate_world_state()

        if outcome.result.succeeded:
            print(
                f"[+] {prepared.implementation} succeeded ({outcome.result.status}), "
                f"{len(processing.evidences)} observations, gain={experience.information_gain}"
            )
        else:
            failure = outcome.result.failure
            print(
                f"[-] {prepared.implementation} {outcome.result.status}: "
                f"{failure.message if failure else 'unknown failure'}"
            )
        return outcome

    # ------------------------------------------------------------- world state

    def publish_world_state(self, force: bool = False) -> WorldState:
        """
        Publish the current ``world-state`` message.

        The result is cached until the state changes, so an iteration publishes once and the
        same message serves as both the planner's input and the experience record's
        ``state_before``. Caching is not a second source of truth: any mutation invalidates it.
        """
        if force or self._world_state_cache is None:
            self._world_state_cache = self.world_publisher.publish(self.state)
            self.audit_logger.log_contract(
                self._world_state_cache, summary=self._world_state_cache.summary()
            )
        return self._world_state_cache

    def invalidate_world_state(self) -> None:
        """Mark the cached world-state message stale after any state mutation."""
        self._world_state_cache = None

    def world_state_for_planning(self, world_state: WorldState, iteration: int = 0) -> WorldState:
        """
        Project out capabilities the policy layer has refused.

        A refusal is environmental information: the Decision Engine should not keep requesting
        an action that cannot be authorised or cannot run here. Permanent refusals (scope
        denial, unknown capability, unsafe parameters) are removed for the rest of the
        assessment; transient ones are removed for ``BLOCK_COOLDOWN_ITERATIONS`` iterations so
        a later change of circumstances can be retried.
        """
        if not self._blocked_capabilities:
            return world_state
        message = world_state.to_message()
        capabilities = message["payload"].get("capabilities") or []
        changed = False
        for capability in capabilities:
            entry = self._blocked_capabilities.get(capability.get("name"))
            if not entry or not capability.get("available"):
                continue
            if not entry["permanent"] and iteration - entry["iteration"] > BLOCK_COOLDOWN_ITERATIONS:
                continue
            capability["available"] = False
            capability["reason"] = f"blocked by policy ({entry['stage']}): {entry['reason']}"
            changed = True
        if not changed:
            return world_state
        return WorldState.parse(message)

    def block_capability(
        self, request: ActionRequest, *, stage: str, reason: str, permanent: bool = True
    ) -> None:
        """Record that a capability must not be re-requested, and why."""
        name = request.implementation or request.capability
        previous = self._blocked_capabilities.get(name)
        if previous is not None and previous["permanent"] and not permanent:
            return
        self._blocked_capabilities[name] = {
            "stage": stage,
            "reason": reason,
            "permanent": bool(permanent),
            "iteration": self._iteration,
            "action_id": request.action_id,
        }
        self.state.extra["blocked_capabilities"] = self._blocked_capabilities
        self.invalidate_world_state()

    @staticmethod
    def closed_gaps(before: WorldState, after: WorldState) -> List[str]:
        """Uncertainty ids that were published before the action and are gone afterwards."""
        before_ids = {item.id for item in before.uncertainties}
        after_ids = {item.id for item in after.uncertainties}
        return sorted(before_ids - after_ids)

    def record_refused(
        self,
        request: ActionRequest,
        result: ExecutionResultContract,
        *,
        validation=None,
        state_before: str = "",
    ) -> ExecutionOutcome:
        """
        Record an action that never ran.

        The attempt still belongs in the execution history and the experience log: an auditor
        has to be able to see that a capability was refused, by which check, and for what
        stated reason.
        """
        self.audit_logger.log_contract(result)
        record = ExecutionRecord(
            id=result.execution_id,
            capability_name=result.implementation or request.capability,
            tool_binary=result.tool.name if result.tool else "",
            interface=result.interface.name if result.interface else request.interface,
            parameters=dict(request.parameters or {}),
            raw_command="",
            exit_code=None,
            duration_seconds=0.0,
            success=False,
            evidence_ids=[],
            failure_reason=result.failure.message if result.failure else result.status,
            information_gain=0.0,
            cost=0.0,
            action_id=request.action_id,
            correlation_id=request.correlation_id,
            status=result.status,
            artifact_ids=[],
        )
        self.applier.apply_execution(self.state, record)
        self.audit_logger.log_execution(record)
        self.invalidate_world_state()

        world_after = self.publish_world_state(force=True)
        experience = self.experience_engine.record(
            request,
            result,
            state_before=state_before or world_after.digest(),
            state_after=world_after.digest(),
            state_revision=world_after.revision,
            new_observations=0,
            gaps_closed=[],
        )
        self.audit_logger.log_contract(
            experience.record,
            summary={"information_gain": 0.0, "useful": False, "status": result.status},
        )
        self.state.extra["experience_scores"] = self.experience_store.get_experience_scores()
        self.invalidate_world_state()
        return ExecutionOutcome(result=result, evidences=[], record=record, validation=validation)

    def rejection_result(
        self, request: ActionRequest, validation
    ) -> ExecutionResultContract:
        """Build the ``execution-result`` for an action the policy layer refused."""
        from ...contracts.envelope import format_timestamp, utc_now

        rejection = dict(validation.rejection or {})
        deferred = validation.status == "deferred"
        category = (
            FailureCategory.SCOPE_DENIED
            if rejection.get("stage") == "scope"
            else FailureCategory.INVALID_PARAMETERS
            if rejection.get("stage") == "parameters"
            else FailureCategory.CAPABILITY_UNAVAILABLE
        )
        now = format_timestamp(utc_now())
        return ExecutionResultContract(
            assessment_id=request.assessment_id,
            source_engine=EngineId.EXECUTION.value,
            correlation_id=request.correlation_id,
            action_id=request.action_id,
            execution_id=f"execution-{request.action_id[:12]}",
            status=ExecutionStatus.UNSUPPORTED if deferred else ExecutionStatus.REJECTED,
            capability=request.capability,
            implementation=request.implementation,
            started_at=now,
            completed_at=now,
            duration_ms=0,
            exit_code=None,
            parameters=dict(request.parameters or {}),
            failure=ExecutionFailure(
                code=category,
                category=category,
                message=str(rejection.get("reason") or f"policy {validation.status} the action"),
                retriable=bool(rejection.get("retriable", False)),
                details={"stage": rejection.get("stage"), "issues": rejection.get("issues") or []},
            ),
            scope_authorised=False,
        )

    # ------------------------------------------------------------- verification

    def verify_findings(self) -> List[VerificationOutcome]:
        """
        Verify open findings through the Verification Engine.

        Replaces the v0.3.0 inline multi-tool heuristic with the same rule set used for
        evidence-driven claims, so one definition of "verified" applies everywhere. Returns the
        outcomes; callers that ignore the return value keep working.
        """
        return self.run_verification_cycle(include_open_findings=True)

    def queue_verification_request(self, request: VerificationRequest) -> None:
        """Queue an evidence-driven verification request, de-duplicated by verification id."""
        if any(existing.verification_id == request.verification_id for existing in self._pending_verification_requests):
            return
        self._pending_verification_requests.append(request)

    def run_verification_cycle(self, include_open_findings: bool = False) -> List[VerificationOutcome]:
        """
        Judge queued verification requests and, optionally, every finding still open.

        Verification never executes a tool. When a conclusion needs more evidence the resulting
        action requests are queued for the Decision Engine, which plans them like any other
        action - that is the ``VerificationActionRequest`` path of specification section 9.
        """
        requests: List[VerificationRequest] = list(self._pending_verification_requests)
        self._pending_verification_requests.clear()

        if include_open_findings:
            known = {request.verification_id for request in requests}
            for finding in self.state.findings:
                if finding.status not in (
                    FindingStatus.HYPOTHESIS,
                    FindingStatus.SUPPORTED,
                    FindingStatus.UNRESOLVED,
                ):
                    continue
                candidate = self.verification_engine.request_for_finding(finding, self.state)
                if candidate.verification_id not in known:
                    requests.append(candidate)
                    known.add(candidate.verification_id)

        outcomes: List[VerificationOutcome] = []
        for request in requests:
            attempts = self._verification_attempts.get(request.verification_id, 0)
            if attempts >= self.max_verification_attempts:
                self.audit_logger.log_event(
                    "verification_skipped",
                    {
                        "verification_id": request.verification_id,
                        "reason": f"attempt limit ({self.max_verification_attempts}) reached",
                    },
                )
                continue
            self._verification_attempts[request.verification_id] = attempts + 1
            outcome = self.verification_engine.verify(request, self.state)
            if outcome is None:
                self.audit_logger.log_event(
                    "verification_unjudgeable",
                    {"verification_id": request.verification_id, "subject": request.subject.to_dict()},
                )
                continue
            self.handle_verification_outcome(outcome, request)
            outcomes.append(outcome)
        return outcomes

    def handle_verification_outcome(
        self, outcome: VerificationOutcome, request: VerificationRequest
    ) -> None:
        """Apply a ``verification-result`` to the World Model and route any follow-up."""
        result = outcome.result
        report = self.applier.apply_verification(self.state, result)
        self.audit_logger.log_contract(result, summary=outcome.summary())
        self.audit_logger.log_verification(
            result.hypothesis_id or result.subject_id or "",
            result.method or "",
            result.status in VerificationStatus.POSITIVE,
            result.supporting_evidence[0] if result.supporting_evidence else None,
        )
        for note in list(report.notes) + list(outcome.notes):
            self.audit_logger.log_event("verification_note", {"verification_id": result.verification_id, "note": note})

        self.state.extra.setdefault("verifications", []).append(
            {
                "verification_id": result.verification_id,
                "status": result.status,
                "method": result.method,
                "confidence": result.confidence,
                "subject_id": result.subject_id,
                "hypothesis_id": result.hypothesis_id,
                "action_id": result.action_id,
                "execution_id": result.execution_id,
                "supporting_evidence": list(result.supporting_evidence),
                "contradicting_evidence": list(result.contradicting_evidence),
                "independent_sources": list(result.independent_sources),
                "required_evidence": [item.to_dict() for item in result.required_evidence],
                "attempts": self._verification_attempts.get(result.verification_id, 0),
            }
        )
        self.invalidate_world_state()

        # Feed the experience store so future action selection knows whether the capability's
        # output survived verification.
        capability = self._capability_for_action(result.action_id)
        if capability:
            self.experience_store.update_verification(
                capability, result.status in VerificationStatus.POSITIVE
            )
            self.state.extra["experience_scores"] = self.experience_store.get_experience_scores()

        if outcome.needs_more_evidence:
            attempts = self._verification_attempts.get(result.verification_id, 0)
            if attempts < self.max_verification_attempts:
                for follow_up in outcome.action_requests:
                    self.queue_verification_action(follow_up)
            else:
                self.audit_logger.log_event(
                    "verification_unresolved",
                    {
                        "verification_id": result.verification_id,
                        "status": result.status,
                        "reason": "attempt limit reached; conclusion remains unresolved",
                        "required_evidence": [item.to_dict() for item in result.required_evidence],
                    },
                )
        if result.status == VerificationStatus.VERIFIED:
            print(
                f"    Verified {result.subject_id} via {result.method} "
                f"(sources: {', '.join(result.independent_sources)}, confidence={result.confidence})"
            )
        elif result.status in VerificationStatus.NEGATIVE:
            print(f"    {result.status.title()} {result.subject_id}: {result.conclusion.details.get('reason', '')}")

    def queue_verification_action(self, request: ActionRequest) -> None:
        """Queue a VerificationActionRequest for the Decision Engine, de-duplicated."""
        key = (request.verification_id, request.capability, request.target.id if request.target else None)
        for existing in self._pending_verification_actions:
            existing_key = (
                existing.verification_id,
                existing.capability,
                existing.target.id if existing.target else None,
            )
            if existing_key == key:
                return
        self._pending_verification_actions.append(request)

    def _capability_for_action(self, action_id: Optional[str]) -> Optional[str]:
        if not action_id:
            return None
        for record in reversed(self.state.execution_history):
            if record.action_id == action_id:
                return record.capability_name
        return None

    def _update_wpa3_findings(self, bssid: str, ap: Any) -> None:
        """Turn observed WPA3 posture into auditable, non-verified findings.

        The model owns Dragonblood reasoning; the assessment engine only projects those
        results into the existing finding store. This keeps the engine from re-parsing RSN
        bytes or knowing how SAE works internally.
        """
        raw = ap.extra.get("wpa3")
        if not isinstance(raw, dict) or not raw.get("akm_suites"):
            return
        allowed = {
            "ssid", "akm_suites", "mfpc", "mfpr", "h2e_advertised", "sae_pk_advertised",
            "sae_groups", "sae_pwe", "anti_clogging_threshold",
            "transition_disable_configured", "implementation", "version", "source",
            "eap_pwd_configured",
        }
        posture = Wpa3Posture(
            bssid=bssid,
            **{key: raw[key] for key in allowed if key in raw},
        )
        for exposure in assess_dragonblood_exposure(posture):
            tag = f"wpa3:{exposure.attack}"
            status = FindingStatus(exposure.status.value)
            existing = next(
                (
                    finding for finding in self.state.findings
                    if tag in finding.tags and bssid in finding.affected_assets
                ),
                None,
            )
            if existing is not None:
                # New capture/configuration evidence may resolve a previous passive
                # unknown. Do not downgrade an independently verified finding, but do
                # refresh hypotheses and unresolved findings with the latest posture.
                if existing.status not in (FindingStatus.VERIFIED, FindingStatus.CONFIRMED):
                    existing.description = exposure.detail
                    existing.details = exposure.to_dict()
                    existing.severity = FindingSeverity(exposure.severity.value)
                    existing.status = status
                    existing.confidence = max(
                        existing.confidence,
                        0.8 if status is FindingStatus.SUPPORTED else 0.4,
                    )
                    for evidence_id in ap.evidence_ids:
                        existing.add_evidence(evidence_id)
                continue
            finding = Finding(
                title=f"WPA3 posture: {exposure.attack}",
                description=exposure.detail,
                category=FindingCategory(exposure.category.value),
                severity=FindingSeverity(exposure.severity.value),
                status=status,
                confidence=0.8 if status is FindingStatus.SUPPORTED else 0.4,
                affected_assets=[bssid],
                details=exposure.to_dict(),
                evidence_ids=list(ap.evidence_ids),
                tags=[tag, "dragonblood", "wpa3"],
            )
            self.state.add_finding(finding)
            self.audit_logger.log_finding(finding)

    def _update_wpa3_auth_findings(self) -> None:
        """Project interface-scoped control-client WPA3 audits into findings."""
        allowed = {
            "akm_suites", "mfpc", "mfpr", "h2e_advertised", "sae_pk_advertised",
            "sae_groups", "sae_pwe", "anti_clogging_threshold",
            "transition_disable_configured", "implementation", "version",
            "source", "eap_pwd_configured",
        }
        for record in self.state.world_model.authentication_observations:
            posture = Wpa3Posture(
                bssid="",
                **{key: record[key] for key in allowed if key in record},
            )
            asset = f"interface:{record.get('interface') or 'local'}"
            evidence_id = record.get("evidence_id")
            for exposure in assess_dragonblood_exposure(posture):
                tag = f"wpa3-config:{exposure.attack}"
                existing = next((
                    finding for finding in self.state.findings
                    if tag in finding.tags and asset in finding.affected_assets
                ), None)
                status = FindingStatus(exposure.status.value)
                if existing is not None:
                    if existing.status not in (FindingStatus.VERIFIED, FindingStatus.CONFIRMED):
                        existing.description = exposure.detail
                        existing.details = exposure.to_dict()
                        existing.status = status
                        existing.severity = FindingSeverity(exposure.severity.value)
                        if evidence_id:
                            existing.add_evidence(evidence_id)
                    continue
                finding = Finding(
                    title=f"WPA3 configuration: {exposure.attack}",
                    description=exposure.detail,
                    category=FindingCategory(exposure.category.value),
                    severity=FindingSeverity(exposure.severity.value),
                    status=status,
                    confidence=0.8 if status is FindingStatus.SUPPORTED else 0.4,
                    affected_assets=[asset],
                    details=exposure.to_dict(),
                    evidence_ids=[evidence_id] if evidence_id else [],
                    tags=[tag, "dragonblood", "wpa3", "configuration"],
                )
                self.state.add_finding(finding)
                self.audit_logger.log_finding(finding)

    def update_findings_from_world_model(self):
        """Generate findings from world model."""
        self._update_wpa3_auth_findings()
        # AP findings
        for bssid, ap in self.state.world_model.access_points.items():
            self._update_wpa3_findings(bssid, ap)
            # Check if we already have finding for this AP
            existing = [f for f in self.state.findings if bssid in f.affected_assets and f.category == FindingCategory.WIRELESS]
            if existing:
                continue

            # Create finding for new AP
            finding = Finding(
                title=f"Access Point Discovered: {ap.ssid or bssid}",
                description=f"Discovered AP BSSID {bssid} SSID {ap.ssid} on channel {ap.channel} with encryption {ap.encryption}",
                category=FindingCategory.WIRELESS,
                severity=FindingSeverity.INFO,
                status=FindingStatus.HYPOTHESIS,
                confidence=0.7,
                affected_assets=[bssid],
                details=ap.to_dict(),
                evidence_ids=ap.evidence_ids,
            )

            # Check for weak encryption
            if ap.encryption:
                weak_enc = [e for e in ap.encryption if e in ["WEP", "WPA", ""]]
                if weak_enc:
                    finding.severity = FindingSeverity.HIGH
                    finding.title = f"Weak Encryption Detected: {ap.ssid or bssid}"
                    finding.description += f" Weak encryption: {weak_enc}"
                    finding.category = FindingCategory.ENCRYPTION

            # Check for WPS enabled
            if ap.wps_enabled:
                wps_finding = Finding(
                    title=f"WPS Enabled: {ap.ssid or bssid}",
                    description=f"AP {bssid} has WPS enabled, which may be vulnerable",
                    category=FindingCategory.WPS,
                    severity=FindingSeverity.MEDIUM,
                    status=FindingStatus.HYPOTHESIS,
                    confidence=0.8,
                    affected_assets=[bssid],
                    details=ap.to_dict(),
                    evidence_ids=ap.evidence_ids,
                )
                self.state.add_finding(wps_finding)
                self.audit_logger.log_finding(wps_finding)

            self.state.add_finding(finding)
            self.audit_logger.log_finding(finding)

    def run(
        self,
        max_iterations: int = 50,
        timeout_per_action: int = 60,
        auto_discover: bool = True,
        verify_every: int = DEFAULT_VERIFY_EVERY,
    ) -> AssessmentState:
        """
        Run the full adaptive assessment through the contract pipeline.

            Observe -> Model -> Identify uncertainty -> Select action -> Parameterize
            -> Execute -> Parse -> Verify -> Update -> Re-evaluate

        Every arrow is a contract message: the World Model publishes ``world-state``, the
        Decision Engine returns ``action-request``, the policy layer returns
        ``action-validation-result``, the Execution Engine returns ``execution-result``, the
        Evidence Engine returns ``evidence-set`` and the Verification Engine returns
        ``verification-result``. No stage reaches into another stage's internals, and a tool
        that cannot run produces an honest non-execution result rather than an empty success.

        ``verify_every`` controls how often open findings are re-examined; verification of
        claims raised by new evidence happens as soon as the evidence arrives.
        """
        print(f"[=== Starting WiFi Assessment {self.state.id} ===]")
        print(f"Scope: {self.scope.to_dict()}")

        self.state.transition_phase(AssessmentPhase.INTERFACE_DISCOVERY, "Starting assessment")
        self.audit_logger.log_state_transition("initializing", "interface_discovery", "Starting")

        if auto_discover:
            self.discover_interfaces()
            self.discover_capabilities()
            self.invalidate_world_state()

            self.state.transition_phase(AssessmentPhase.CAPABILITY_DISCOVERY, "Interfaces discovered")
            self.audit_logger.log_state_transition("interface_discovery", "capability_discovery", "Interfaces discovered")

            self.state.transition_phase(AssessmentPhase.WIRELESS_OBSERVATION, "Capabilities discovered")
            self.audit_logger.log_state_transition("capability_discovery", "wireless_observation", "Capabilities discovered")

        verify_interval = max(1, int(verify_every))
        while self._iteration < max_iterations:
            self._iteration += 1
            iteration = self._iteration
            print(f"\n[--- Iteration {iteration} Phase: {self.state.phase.value} ---]")

            world_state = self.publish_world_state()
            request: Optional[ActionRequest] = None

            # 1. A pending verification requirement is an already-justified reason to act, so
            #    it is planned before any newly identified gap.
            if self._pending_verification_actions:
                candidates = list(self._pending_verification_actions)
                self._pending_verification_actions.clear()
                request = self.decision_engine.plan_verification(candidates, world_state)
                if request is None:
                    print("[*] No available capability can satisfy the pending verification requirement")
                    self.audit_logger.log_event(
                        "verification_action_unsatisfiable",
                        {
                            "requested": [item.to_dict() for item in candidates],
                            "reason": "no available capability produces the required observation",
                        },
                    )
                else:
                    print(
                        f"[*] Planning verification action for {request.verification_id} "
                        f"(subject={request.target.id})"
                    )

            # 2. Otherwise plan from the published state, minus anything policy has refused.
            if request is None:
                planning_state = self.world_state_for_planning(world_state, iteration)
                if not self.decision_engine.should_continue(planning_state, max_iterations):
                    print("[*] Decision engine reports no further useful action")
                    break
                request = self.decision_engine.plan(planning_state)

            if request is None:
                print("[*] No further actions planned, checking phase transition")
                next_phase = self.decision_engine.suggest_phase_transition(world_state)
                if next_phase and next_phase != self.state.phase:
                    self._apply_phase_transition(next_phase, "Planner suggested transition")
                    if next_phase == AssessmentPhase.COMPLETED:
                        break
                    continue
                print("[*] No phase transition available, assessment complete")
                break

            # 3. Run the pipeline for this action.
            self.execute_action_request(request, timeout=timeout_per_action, world_state=world_state)

            # 4. Derive findings from the updated World Model, then verify.
            self.update_findings_from_world_model()
            self.invalidate_world_state()
            if iteration % verify_interval == 0:
                self.run_verification_cycle(include_open_findings=True)

            # 5. Re-evaluate the phase from the state the actions actually produced.
            next_phase = self.decision_engine.suggest_phase_transition(self.publish_world_state())
            if next_phase and next_phase != self.state.phase:
                self._apply_phase_transition(next_phase, "Automatic phase progression")

        # Final verification pass before reporting, so the report states conclusions the
        # framework actually reached rather than hypotheses it never tested.
        self.run_verification_cycle(include_open_findings=True)

        self.state.transition_phase(AssessmentPhase.REPORTING, "Assessment loop completed")
        self.audit_logger.log_state_transition(self.state.phase.value, "reporting", "Loop completed")

        report_path = self.audit_logger.save_report(self.state)
        print("\n[=== Assessment Completed ===]")
        print(f"Report saved to: {report_path}")
        print(f"Artifacts: {self.artifact_store.stats().to_dict()}")
        print(f"Summary: {self.state.summary()}")

        self.state.transition_phase(AssessmentPhase.COMPLETED, "Report generated")
        self.audit_logger.log_state_transition("reporting", "completed", "Report generated")

        return self.state

    def _apply_phase_transition(self, next_phase: AssessmentPhase, reason: str) -> None:
        """Move the assessment to a new phase and record the transition."""
        old_phase = self.state.phase.value
        print(f"[*] Transitioning phase {old_phase} -> {next_phase.value}")
        self.state.transition_phase(next_phase, reason)
        self.audit_logger.log_state_transition(old_phase, next_phase.value, reason)
        self.invalidate_world_state()
