"""
Tests for the Decision Engine's AI-layer integration point.

``planning_context()`` and ``accept_proposal()`` are the seam where an optional AI planner plugs
in. Two properties matter more than convenience here:

1. The context handed to the AI layer is **narrower** than the WorldState - raw observations and
   evidence payloads are summarised, not forwarded, so the layer cannot act on details it was
   never given and cannot reconstruct a command from them.
2. Acceptance is **not** authorisation. A proposal converted into an ``action-request`` still has
   to pass the policy layer, which owns scope.
"""
from __future__ import annotations

import pytest

from wifi_framework.contracts import (
    ActionOrigin,
    ActionRequest,
    CapabilityState,
    Claim,
    DecisionProposal,
    EngineId,
    EntityRef,
    HypothesisRef,
    PlanningContext,
    TargetType,
    UncertaintyRef,
    WorldState,
)
from wifi_framework.contracts.world_state import AccessPointState
from wifi_framework.core.decision import DecisionEngine
from wifi_framework.core.execution.registry import CapabilityRegistry
from wifi_framework.core.models.scope import AssessmentScope
from wifi_framework.core.policy import ActionPolicy
from wifi_framework.tools.registry_loader import load_all_adapters

ASSESSMENT = "77777777-7777-4777-8777-777777777777"
IN_SCOPE = "AA:BB:CC:DD:EE:FF"
OUT_OF_SCOPE = "11:22:33:44:55:66"


@pytest.fixture(scope="module")
def registry() -> CapabilityRegistry:
    loaded = CapabilityRegistry()
    load_all_adapters(loaded)
    return loaded


def capability(name: str, *, available: bool = True, category: str = "wireless_observation",
               outputs=None, invasive: bool = False, reason: str | None = None) -> CapabilityState:
    return CapabilityState(
        name=name,
        available=available,
        reason=reason,
        category=category,
        tool_binary=name,
        inputs=["interface"],
        outputs=list(outputs or ["access_points"]),
        interface_required=True,
        invasive=invasive,
    )


def world_state(**overrides) -> WorldState:
    kwargs = dict(
        assessment_id=ASSESSMENT,
        phase="wireless_observation",
        revision=7,
        scope={"authorized_bssids": [IN_SCOPE], "strict_mode": False},
        objective={"description": "assess TestNet"},
        capabilities=[
            capability("airodump-ng"),
            capability("wash", category="wps_assessment", outputs=["wps_observations"]),
            capability("aireplay-ng", invasive=True, outputs=["injection_test"]),
            capability("reaver", available=False, category="wps_assessment",
                       outputs=["wps_observations"], reason="Tool 'reaver' not found"),
            capability("hcxdumptool", available=False, category="handshake_capture",
                       outputs=["handshakes"], reason="Tool 'hcxdumptool' not found"),
        ],
        uncertainties=[
            UncertaintyRef(id="gap-1", type="wireless_observation", priority=9,
                           description="no access points observed", required_capabilities=["airodump-ng"]),
        ],
        access_points=[
            AccessPointState(id=IN_SCOPE, ssid="TestNet", channel=6, in_scope=True),
            AccessPointState(id=OUT_OF_SCOPE, ssid="Neighbour", channel=11, in_scope=False),
        ],
    )
    kwargs.update(overrides)
    return WorldState(**kwargs)


def proposal(**overrides) -> DecisionProposal:
    kwargs = dict(
        assessment_id=ASSESSMENT,
        capability="wireless_observation",
        target=EntityRef(type=TargetType.ACCESS_POINT.value, id=IN_SCOPE),
        reasoning_summary="no access points have been observed yet",
        confidence=0.8,
        information_gaps=["gap-1"],
    )
    kwargs.update(overrides)
    return DecisionProposal(**kwargs)


# ------------------------------------------------------------- planning context


def test_context_is_a_valid_contract_bound_to_the_published_state(registry):
    engine = DecisionEngine(registry)
    context = engine.planning_context(world_state())

    assert isinstance(context, PlanningContext)
    assert context.source_engine == EngineId.DECISION.value
    assert context.assessment_id == ASSESSMENT
    assert context.state_revision == 7
    assert context.validate().ok
    assert PlanningContext.parse(context.to_message()).to_dict() == context.to_dict()


def test_context_declares_that_the_ai_layer_may_not_invoke_a_shell(registry):
    context = DecisionEngine(registry).planning_context(world_state())
    assert context.constraints["may_not_invoke_shell"] is True
    assert context.constraints["must_name_registered_capability"] is True
    assert context.constraints["scope"]["authorized_bssids"] == [IN_SCOPE]


def test_context_offers_only_available_capabilities(registry):
    context = DecisionEngine(registry).planning_context(world_state())
    names = {item["name"] for item in context.available_capabilities}
    assert names == {"airodump-ng", "wash", "aireplay-ng"}
    assert context.capability_names() == sorted(names)


def test_context_excludes_out_of_scope_assets(registry):
    context = DecisionEngine(registry).planning_context(world_state())
    ap_ids = {ap["id"] for ap in context.relevant_state["access_points"]}
    assert ap_ids == {IN_SCOPE}
    assert context.relevant_state["phase"] == "wireless_observation"
    assert context.relevant_state["revision"] == 7


def test_context_does_not_forward_raw_observations(registry):
    """The narrowed projection is the point: no raw evidence, no commands to reconstruct."""
    state = world_state()
    context = DecisionEngine(registry).planning_context(state)
    assert "observations" not in context.relevant_state
    assert "evidence" not in context.relevant_state
    serialised = context.to_message()
    assert "raw_command" not in str(serialised)
    assert "raw_output" not in str(serialised)


def test_context_carries_information_gaps_and_experience_hints(registry):
    engine = DecisionEngine(registry)
    context = engine.planning_context(
        world_state(),
        experience=[{"capability": "wireless_observation", "information_gain": 0.6}],
    )
    assert [gap["id"] for gap in context.information_gaps] == ["gap-1"]
    assert context.relevant_experience[0]["information_gain"] == 0.6


def test_objective_can_be_supplied_and_otherwise_comes_from_the_state(registry):
    engine = DecisionEngine(registry)
    assert engine.planning_context(world_state()).objective == {"description": "assess TestNet"}
    supplied = engine.planning_context(world_state(), objective={"description": "confirm WPS"})
    assert supplied.objective == {"description": "confirm WPS"}


@pytest.mark.parametrize(
    "field,count,limit",
    [("access_points", 60, 50), ("hypotheses", 30, 25), ("findings", 30, 25), ("execution_summary", 15, 10)],
)
def test_context_truncates_bulk_sections(registry, field, count, limit):
    """An AI layer must not be handed an unbounded payload."""
    if field == "access_points":
        entries = [AccessPointState(id=f"AA:BB:CC:DD:EE:{i:02x}", ssid=f"net{i}", in_scope=True)
                   for i in range(count)]
        state = world_state(access_points=entries)
    elif field in ("hypotheses", "findings"):
        entries = [
            HypothesisRef(id=f"finding-{i}", title=f"t{i}", description="d", status="supported",
                          category="wps", severity="medium", confidence=0.5)
            for i in range(count)
        ]
        state = world_state(**{field: entries})
    else:
        state = world_state(
            execution_summary=[{"execution_id": f"execution-{i}", "status": "success"} for i in range(count)]
        )

    context = DecisionEngine(registry).planning_context(state)
    if field == "execution_summary":
        projected = context.relevant_state["recent_executions"]
    elif field == "access_points":
        projected = context.relevant_state["access_points"]
    elif field == "hypotheses":
        projected = context.relevant_state["open_hypotheses"]
    else:
        projected = context.relevant_state["confirmed_findings"]
    assert len(projected) == limit


# ------------------------------------------------------------- proposal intake


def test_valid_proposal_becomes_an_action_request(registry):
    request, problems = DecisionEngine(registry).accept_proposal(proposal(), world_state())

    assert isinstance(request, ActionRequest)
    assert problems == []
    assert request.origin == ActionOrigin.AI_PROPOSAL
    assert request.capability == "wireless_observation"
    assert request.implementation == "airodump-ng"
    assert request.action_id  # freshly minted, not reused from the proposal
    assert request.reason.summary == "no access points have been observed yet"
    assert request.validate().ok


def test_structurally_invalid_proposal_is_refused(registry):
    bad = proposal(capability="")
    request, problems = DecisionEngine(registry).accept_proposal(bad, world_state())
    assert request is None
    assert problems


def test_proposal_for_another_assessment_is_refused(registry):
    """Cross-assessment confusion is a hard refusal, not a warning."""
    foreign = proposal(assessment_id="88888888-8888-4888-8888-888888888888")
    request, problems = DecisionEngine(registry).accept_proposal(foreign, world_state())
    assert request is None
    assert any("88888888" in problem for problem in problems)


def test_proposal_naming_an_unknown_capability_is_refused(registry):
    request, problems = DecisionEngine(registry).accept_proposal(
        proposal(capability="telepathy", implementation="not-a-tool"), world_state()
    )
    assert request is None
    assert any("not an available capability" in problem for problem in problems)


def test_proposal_naming_an_unavailable_implementation_is_substituted_and_recorded(registry):
    """
    Running a substitute for a missing tool is legitimate, but the swap must be auditable:
    the AI asked for ``reaver``, the framework will run ``wash``, and the trail says so.
    """
    request, problems = DecisionEngine(registry).accept_proposal(
        proposal(capability="wps_assessment", implementation="reaver"), world_state()
    )
    assert request is not None
    assert request.implementation == "wash"
    assert any("reaver" in problem and "wash" in problem for problem in problems)


def test_proposal_that_nothing_available_can_fulfil_is_refused(registry):
    request, problems = DecisionEngine(registry).accept_proposal(
        proposal(capability="handshake_capture", implementation="hcxdumptool",
                 expected_outputs=["handshakes"]),
        world_state(),
    )
    assert request is None
    assert any("no available capability can fulfil" in problem for problem in problems)


def test_category_level_proposal_is_resolved_to_an_available_implementation(registry):
    """Naming the category rather than a tool is legitimate; the engine resolves it."""
    request, problems = DecisionEngine(registry).accept_proposal(
        proposal(capability="wps_assessment", expected_outputs=["wps_observations"]), world_state()
    )
    assert problems == []
    assert request.implementation == "wash"  # reaver is unavailable


def test_citing_a_nonexistent_gap_is_recorded_but_not_fatal(registry):
    """A reasoning error is audited; the request is still built and still judged downstream."""
    request, problems = DecisionEngine(registry).accept_proposal(
        proposal(information_gaps=["gap-1", "gap-invented"]), world_state()
    )
    assert request is not None
    assert any("gap-invented" in problem for problem in problems)


def test_low_confidence_proposal_is_accepted_but_flagged(registry):
    request, problems = DecisionEngine(registry).accept_proposal(proposal(confidence=0.2), world_state())
    assert request is not None
    assert any("below 0.5" in problem for problem in problems)


def test_acceptance_is_not_authorisation(registry):
    """
    The seam's most important property: an accepted proposal still faces the policy layer.

    The AI layer may propose an invasive action against a target; only policy decides whether it
    may run. Here the proposal is accepted, and the policy layer then refuses it on scope.
    """
    engine = DecisionEngine(registry)
    state = world_state()
    request, problems = engine.accept_proposal(
        proposal(
            capability="wireless_observation",
            implementation="aireplay-ng",
            target=EntityRef(type=TargetType.ACCESS_POINT.value, id=OUT_OF_SCOPE),
            parameters={"bssid": OUT_OF_SCOPE, "action": "deauth"},
        ),
        state,
    )
    assert problems == []
    assert request is not None

    scope = AssessmentScope(authorized_bssids=[IN_SCOPE])
    from wifi_framework.core.models.assessment_state import AssessmentState

    assessment = AssessmentState(scope=scope)
    assessment.id = ASSESSMENT
    verdict = ActionPolicy(registry=registry, scope=scope).validate(request, assessment)
    assert verdict.approved is False
    assert verdict.rejection["code"] == "scope_denied_wireless"


def test_proposal_cannot_carry_a_command(registry):
    """Even at the intake seam, a command in the payload is rejected rather than ignored."""
    message = proposal().to_message()
    message["payload"]["command"] = "airodump-ng -i wlan0mon"
    with pytest.raises(Exception) as excinfo:
        DecisionProposal.parse(message)
    assert "shell" in str(excinfo.value).lower()
