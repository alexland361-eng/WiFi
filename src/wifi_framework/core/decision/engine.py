"""
Decision Engine.

Consumes ``world-state``, emits ``action-request``. Nothing else.

The engine answers three questions in order, which is the adaptive loop the project is built
around: what is unknown (uncertainties published in the WorldState), which capability could
reduce that uncertainty, and how should the request be expressed so the Execution Engine can
implement it. It never builds a command and never touches a tool.

Heuristics are reused from :mod:`wifi_framework.core.planning` rather than reimplemented, but
they run against :class:`~wifi_framework.core.decision.state_view.WorldStateView`, so their
only input is the contract message.

The optional AI layer plugs in through :meth:`planning_context` and :meth:`accept_proposal`.
A ``decision-proposal`` is converted into an ordinary ``action-request`` and then passes the
same policy validation as a planner-produced request; the AI layer cannot reach the operating
system through this contract.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ...contracts.action import ActionObjective, ActionOrigin, ActionReason, ActionRequest
from ...contracts.ai import DecisionProposal, PlanningContext
from ...contracts.common import EntityRef, TargetType
from ...contracts.envelope import EngineId
from ...contracts.world_state import CapabilityState, UncertaintyRef, WorldState
from ..planning.action_selector import UNCERTAINTY_OUTPUT_MAP
from ..planning.planner import AssessmentPlanner
from .state_view import ContractRegistryView, WorldStateView

#: Uncertainty types whose resolution must be confirmed by verification before it is believed.
_VERIFICATION_TRIGGERING_GAPS = {"verification", "wps_state", "handshake_capture", "hidden_ssid"}

#: Maximum supporting-evidence references carried on an ActionRequest.
_MAX_SUPPORTING_EVIDENCE = 5


class DecisionEngine:
    """Turns the published assessment state into the next action request."""

    def __init__(self, registry: Any) -> None:
        self.registry = registry

    # ------------------------------------------------------------------ planning

    def plan(self, world_state: WorldState) -> Optional[ActionRequest]:
        """
        Select the next useful action, or ``None`` when the state shows nothing worth doing.

        ``None`` is a meaningful answer: it means the WorldState exposes no uncertainty that an
        available capability could reduce, which is how an assessment completes instead of
        running tools for their own sake.
        """
        view = WorldStateView(world_state, self.registry)
        planner = AssessmentPlanner(ContractRegistryView(self.registry, view))
        selected = planner.plan_next_action(view)
        if not selected:
            return None
        return self._to_action_request(selected, world_state, view)

    def should_continue(self, world_state: WorldState, max_iterations: int = 100) -> bool:
        """Delegate the continuation decision to the same heuristics, on contract data."""
        view = WorldStateView(world_state, self.registry)
        planner = AssessmentPlanner(ContractRegistryView(self.registry, view))
        return planner.should_continue(view, max_iterations)

    def suggest_phase_transition(self, world_state: WorldState) -> Optional[Any]:
        """Return the phase the assessment should move to, or ``None`` to stay."""
        view = WorldStateView(world_state, self.registry)
        planner = AssessmentPlanner(ContractRegistryView(self.registry, view))
        return planner.suggest_phase_transition(view)

    def select_interface(self, world_state: WorldState, capability_name: str) -> Optional[str]:
        """Choose an interface for a capability from the published interface state."""
        metadata = self.registry.get_metadata(capability_name)
        if metadata is None or not metadata.requirements.interface_required:
            return None
        needs_monitor = "monitor_mode" in metadata.requirements.interface_capabilities
        candidates = list(world_state.interfaces)
        if needs_monitor:
            candidates = [item for item in candidates if item.supports_monitor] or []
        if not candidates:
            return None
        # Prefer an interface that is up, then one whose capabilities were actually probed.
        candidates.sort(key=lambda item: (not bool(item.is_up), not item.probed, item.name))
        return candidates[0].name

    # ------------------------------------------------------- verification routing

    def plan_verification(
        self, requests: Sequence[ActionRequest], world_state: WorldState
    ) -> Optional[ActionRequest]:
        """
        Choose the first VerificationActionRequest that this environment can actually satisfy.

        The Verification Engine names a capability *category*; resolving it to a concrete,
        available tool is the Decision Engine's job. A request that nothing available can
        satisfy is returned as ``None`` so the caller can record the limitation instead of
        attempting an action that must fail.
        """
        for request in requests:
            resolved = self.resolve_implementation(request, world_state)
            if resolved is not None:
                return resolved
        return None

    def resolve_implementation(
        self, action: ActionRequest, world_state: WorldState
    ) -> Optional[ActionRequest]:
        """
        Fill in a concrete implementation and interface for a request that lacks them.

        Returns ``None`` when no available capability can fulfil the request; the reason is
        recorded in the returned-None case by the caller's audit trail.
        """
        available = {item.name: item for item in world_state.available_capabilities()}
        implementation = action.implementation

        if implementation and implementation in available:
            chosen: Optional[CapabilityState] = available[implementation]
        else:
            chosen = self._select_implementation(action, list(available.values()))
            if chosen is None:
                return None
            implementation = chosen.name

        interface = action.interface
        if chosen.interface_required and not interface:
            interface = self._select_interface_for(chosen, world_state)
            if interface is None:
                return None

        if implementation == action.implementation and interface == action.interface:
            return action
        return action.with_resolution(implementation=implementation, interface=interface, prepared=action.prepared)

    def _select_implementation(
        self, action: ActionRequest, candidates: Sequence[CapabilityState]
    ) -> Optional[CapabilityState]:
        """Deterministic choice among capabilities that could fulfil the request."""
        wanted_outputs = set(action.expected_outputs or [])
        matching: List[CapabilityState] = []
        for candidate in candidates:
            if action.capability == candidate.name or action.capability == candidate.category:
                matching.append(candidate)
                continue
            if wanted_outputs and wanted_outputs & set(candidate.outputs):
                matching.append(candidate)
        if not matching:
            # Fall back to any capability that can produce the expected observation.
            matching = [
                candidate
                for candidate in candidates
                if wanted_outputs and wanted_outputs & set(candidate.outputs)
            ]
        if not matching:
            return None
        # Prefer non-invasive, then short-running, then alphabetical for determinism.
        matching.sort(
            key=lambda item: (
                item.invasive,
                item.estimated_duration_seconds if item.estimated_duration_seconds is not None else 10 ** 6,
                item.name,
            )
        )
        return matching[0]

    @staticmethod
    def _select_interface_for(capability: CapabilityState, world_state: WorldState) -> Optional[str]:
        needs_monitor = "monitor_mode" in capability.interface_capabilities
        candidates = list(world_state.interfaces)
        if needs_monitor:
            candidates = [item for item in candidates if item.supports_monitor]
        if not candidates:
            return None
        candidates.sort(key=lambda item: (not bool(item.is_up), not item.probed, item.name))
        return candidates[0].name

    # ------------------------------------------------------------------- AI layer

    def planning_context(
        self,
        world_state: WorldState,
        *,
        experience: Optional[Sequence[Dict[str, Any]]] = None,
        objective: Optional[Dict[str, Any]] = None,
    ) -> PlanningContext:
        """
        Build the constrained view handed to an optional AI planner.

        Deliberately narrower than the WorldState: raw observations and evidence payloads are
        summarised, not forwarded, so the AI layer cannot act on details it has not been given
        and cannot reconstruct a command from them.
        """
        payload = objective or dict(world_state.objective or {})
        relevant_state = {
            "phase": world_state.phase,
            "revision": world_state.revision,
            "summary": world_state.summary(),
            "interfaces": [item.to_dict() for item in world_state.interfaces],
            "access_points": [item.to_dict() for item in world_state.in_scope_access_points()[:50]],
            "clients_count": len(world_state.clients),
            "networks": [
                {"id": network.id, "cidr": network.cidr, "in_scope": network.in_scope, "hosts": len(network.hosts)}
                for network in world_state.networks
            ],
            "open_hypotheses": [item.to_dict() for item in world_state.hypotheses[:25]],
            "confirmed_findings": [item.to_dict() for item in world_state.findings[:25]],
            "recent_executions": world_state.execution_summary[-10:],
        }
        return PlanningContext(
            assessment_id=world_state.assessment_id,
            source_engine=EngineId.DECISION.value,
            correlation_id=world_state.correlation_id,
            objective=payload,
            relevant_state=relevant_state,
            information_gaps=[item.to_dict() for item in world_state.uncertainties],
            available_capabilities=[item.to_dict() for item in world_state.available_capabilities()],
            relevant_experience=[dict(item) for item in (experience or [])],
            constraints={
                "scope": dict(world_state.scope or {}),
                "may_not_invoke_shell": True,
                "must_name_registered_capability": True,
            },
            state_revision=world_state.revision,
        )

    def accept_proposal(
        self, proposal: DecisionProposal, world_state: WorldState
    ) -> Tuple[Optional[ActionRequest], List[str]]:
        """
        Validate a ``decision-proposal`` and convert it into an ``action-request``.

        Returns ``(request, problems)``. The request is ``None`` when the proposal cannot be
        accepted; ``problems`` always explains why, and is audited either way. Acceptance here
        is *not* authorisation: the resulting request still passes the policy layer.
        """
        problems: List[str] = []
        structural = proposal.validate()
        if not structural.ok:
            problems.extend(structural.error_messages)
            return None, problems

        if proposal.assessment_id != world_state.assessment_id:
            problems.append(
                f"proposal refers to assessment {proposal.assessment_id!r} but the current "
                f"assessment is {world_state.assessment_id!r}"
            )
            return None, problems

        available = {item.name for item in world_state.available_capabilities()}
        categories = {item.category for item in world_state.capabilities if item.category}
        implementation = proposal.implementation or proposal.capability
        if implementation not in available and proposal.capability not in categories:
            problems.append(
                f"proposal names '{proposal.capability}' (implementation '{implementation}') "
                "which is not an available capability in the published state"
            )
            return None, problems
        if implementation not in available:
            resolved = self._select_implementation(
                ActionRequest(
                    assessment_id=proposal.assessment_id,
                    action_id="proposal-resolution",
                    capability=proposal.capability,
                    expected_outputs=list(proposal.expected_outputs),
                ),
                list(world_state.available_capabilities()),
            )
            if resolved is None:
                problems.append(f"no available capability can fulfil '{proposal.capability}'")
                return None, problems
            implementation = resolved.name

        known_gaps = {item.id for item in world_state.uncertainties}
        unknown_gaps = [gap for gap in proposal.information_gaps if gap not in known_gaps]
        if unknown_gaps:
            problems.append(
                f"proposal cites information gaps not present in the published state: {unknown_gaps}"
            )
            # Citing a gap that does not exist is a reasoning error, not a fatal one: the
            # request is still built, but the audit trail records the discrepancy.

        request = proposal.to_action_request(
            action_id=str(uuid.uuid4()), correlation_id=proposal.correlation_id
        )
        if request.implementation != implementation:
            request = request.with_resolution(implementation=implementation)
        if proposal.confidence < 0.5:
            problems.append(
                f"proposal confidence {proposal.confidence} is below 0.5; accepted but flagged"
            )
        return request, problems

    # ------------------------------------------------------------------ internals

    def _to_action_request(
        self, selected: Dict[str, Any], world_state: WorldState, view: WorldStateView
    ) -> ActionRequest:
        """Convert the heuristic selection into the ``action-request`` contract."""
        metadata = selected.get("capability_metadata")
        uncertainty: Dict[str, Any] = dict(selected.get("uncertainty") or {})
        implementation = selected.get("capability_name")
        capability = self._capability_name(metadata, implementation)
        gap_id = self._gap_id(uncertainty, world_state)
        target = self._target(uncertainty, view, world_state)
        parameters = self._parameter_hints(uncertainty, target, world_state)
        expected_outputs = self._expected_outputs(uncertainty, metadata)
        invasive = bool(metadata.operational_properties.invasive) if metadata is not None else False

        return ActionRequest(
            assessment_id=world_state.assessment_id,
            source_engine=EngineId.DECISION.value,
            correlation_id=world_state.correlation_id,
            action_id=str(uuid.uuid4()),
            capability=capability,
            objective=ActionObjective.RESOLVE_INFORMATION_GAP,
            target=target,
            parameters=parameters,
            prerequisites=self._prerequisites(metadata),
            expected_outputs=expected_outputs,
            verification_required=self._verification_required(uncertainty, metadata, invasive),
            reason=ActionReason(
                information_gaps=[gap_id] if gap_id else [],
                supporting_evidence=self._supporting_evidence(target, view),
                summary=str(selected.get("reason") or ""),
                uncertainty_type=str(uncertainty.get("type") or "") or None,
                score=selected.get("score"),
            ),
            implementation=implementation,
            interface=selected.get("interface"),
            origin=ActionOrigin.PLANNER,
            priority=int(uncertainty.get("priority") or 0),
        )

    @staticmethod
    def _capability_name(metadata: Any, implementation: Optional[str]) -> str:
        """The capability being requested, expressed as the operation rather than the tool."""
        if metadata is not None:
            category = metadata.category.value if hasattr(metadata.category, "value") else str(metadata.category)
            if category:
                return category
        return implementation or "unknown"

    @staticmethod
    def _gap_id(uncertainty: Dict[str, Any], world_state: WorldState) -> Optional[str]:
        """Resolve the selected uncertainty to its stable published gap id."""
        utype = str(uncertainty.get("type") or "")
        if not utype:
            return None
        for item in world_state.uncertainties:
            if item.type == utype:
                return item.id
        # The planner may have recomputed uncertainties from the same state; derive the id the
        # same way the publisher does so citations stay resolvable.
        from ..world.state_publisher import uncertainty_id

        subjects: List[str] = []
        context = uncertainty.get("context") or {}
        for key in ("bssids", "finding_ids", "ips", "interfaces", "macs"):
            value = context.get(key)
            if isinstance(value, list):
                subjects.extend(str(item) for item in value)
        return uncertainty_id(utype, subjects)

    @staticmethod
    def _target(uncertainty: Dict[str, Any], view: WorldStateView, world_state: WorldState) -> EntityRef:
        """Derive the subject of the action from the uncertainty's context."""
        context = uncertainty.get("context") or {}
        utype = str(uncertainty.get("type") or "")
        bssids = context.get("bssids")
        if isinstance(bssids, list) and bssids:
            return EntityRef(type=TargetType.ACCESS_POINT.value, id=str(bssids[0]).upper())
        finding_ids = context.get("finding_ids")
        if isinstance(finding_ids, list) and finding_ids:
            finding = next((item for item in view.findings if item.id == finding_ids[0]), None)
            if finding is not None and finding.affected_assets:
                return EntityRef(type=TargetType.ACCESS_POINT.value, id=str(finding.affected_assets[0]))
            return EntityRef(type=TargetType.FINDING.value, id=str(finding_ids[0]))
        if utype == "interface_discovery" and view.interfaces:
            return EntityRef(type=TargetType.INTERFACE.value, id=sorted(view.interfaces)[0])
        if utype == "network_hosts" and world_state.networks:
            return EntityRef(type=TargetType.NETWORK.value, id=world_state.networks[0].id)
        return EntityRef(type=TargetType.NONE.value)

    @staticmethod
    def _parameter_hints(uncertainty: Dict[str, Any], target: EntityRef, world_state: WorldState) -> Dict[str, Any]:
        """
        Hints only. The Execution Engine derives the real parameters from assessment state.

        A hint is added only when it is unambiguous: naming one of several observed BSSIDs as
        if it were the only candidate would silently narrow the assessment.
        """
        hints: Dict[str, Any] = {}
        context = uncertainty.get("context") or {}
        bssids = context.get("bssids")
        if isinstance(bssids, list) and len(bssids) == 1:
            hints["bssid"] = str(bssids[0]).upper()
        elif target.type == TargetType.ACCESS_POINT.value and target.id:
            observed = [ap.id for ap in world_state.access_points if ap.in_scope is not False]
            if len(observed) == 1:
                hints["bssid"] = observed[0]
        channels = context.get("channels_observed")
        if isinstance(channels, list) and len(channels) == 1:
            hints["channel"] = int(channels[0])
        elif len(world_state.scope.get("authorized_channels") or []) == 1:
            hints["channel"] = int(world_state.scope["authorized_channels"][0])
        return hints

    @staticmethod
    def _expected_outputs(uncertainty: Dict[str, Any], metadata: Any) -> List[str]:
        """Outputs the action must produce to count as useful, intersected with what it can do."""
        utype = str(uncertainty.get("type") or "")
        wanted = UNCERTAINTY_OUTPUT_MAP.get(utype, [])
        if metadata is None:
            return list(wanted)
        produced = list(metadata.outputs or [])
        return [output for output in wanted if output in produced]

    @staticmethod
    def _prerequisites(metadata: Any) -> List[str]:
        if metadata is None:
            return []
        prerequisites = [f"tool:{metadata.tool_binary}"]
        requirements = metadata.requirements
        if requirements.interface_required:
            prerequisites.append("interface")
        for capability in requirements.interface_capabilities:
            prerequisites.append(str(capability))
        for privilege in requirements.privileges:
            prerequisites.append(f"privilege:{privilege}")
        for dependency in requirements.dependencies:
            prerequisites.append(f"dependency:{dependency}")
        return prerequisites

    @staticmethod
    def _verification_required(uncertainty: Dict[str, Any], metadata: Any, invasive: bool) -> bool:
        utype = str(uncertainty.get("type") or "")
        if utype in _VERIFICATION_TRIGGERING_GAPS:
            return True
        if invasive:
            # Anything that touches the environment must be confirmed by observation afterwards.
            return True
        if metadata is not None:
            outputs = set(metadata.outputs or [])
            if outputs & {"handshake", "wps_observations", "vulnerability", "credential_observation"}:
                return True
        return False

    @staticmethod
    def _supporting_evidence(target: EntityRef, view: WorldStateView) -> List[str]:
        if not target.id:
            return []
        matched = [
            evidence.id
            for evidence in view.evidences
            if str((evidence.parsed_data or {}).get("bssid", "")).upper() == str(target.id).upper()
            or str((evidence.parsed_data or {}).get("mac", "")).upper() == str(target.id).upper()
            or str((evidence.parsed_data or {}).get("ip", "")) == str(target.id)
        ]
        return matched[:_MAX_SUPPORTING_EVIDENCE]



