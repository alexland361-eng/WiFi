"""Contradictory evidence is preserved, not silently overwritten.

The framework's stated invariant (`core/world/state_publisher.py`) is that
observations are never silently overwritten. These tests drive the real pipeline -
EvidenceEngine -> WorldModelApplier -> VerificationEngine - with observations that
disagree about the same access point, and pin what happens at each layer.

They exist because the property is easy to break without noticing. If the applier
ever deduplicated by subject instead of by evidence id, or if `AccessPoint` stored a
single `encryption` string instead of accumulating, the Verification Engine's
contradiction rules would stop firing: `_gather` reads `state.evidences`, so an
overwritten observation simply never reaches it, and a claim would be promoted on
evidence that had quietly disappeared. Every assertion here was measured against the
running pipeline rather than inferred from the design.
"""
from __future__ import annotations

import pytest

from wifi_framework.contracts.action import ActionRequest
from wifi_framework.contracts.common import InterfaceRef, ToolRef
from wifi_framework.contracts.execution import ExecutionResult, ExecutionStatus
from wifi_framework.contracts.verification import VerificationStatus
from wifi_framework.core.evidence import EvidenceEngine
from wifi_framework.core.models.assessment_state import AssessmentState
from wifi_framework.core.models.evidence import ConfidenceLevel, Evidence, EvidenceType
from wifi_framework.core.models.scope import AssessmentScope
from wifi_framework.core.verification.engine import (
    CONTRADICT_TOLERANCE,
    REFUTE_MARGIN,
    VerificationEngine,
    noisy_or,
)
from wifi_framework.core.world.applier import WorldModelApplier

BSSID = "AA:BB:CC:DD:EE:FF"
ASSESSMENT = "33333333-3333-4333-8333-333333333333"


def _execution(execution_id: str, tool: str) -> ExecutionResult:
    return ExecutionResult(
        assessment_id=ASSESSMENT,
        action_id=f"action-{execution_id}",
        execution_id=execution_id,
        capability="wireless_observation",
        implementation=tool,
        status=ExecutionStatus.SUCCESS,
        exit_code=0,
        duration_ms=100,
        tool=ToolRef(name=tool, version="1.7"),
        interface=InterfaceRef(name="wlan0mon"),
        command=[tool, "--bssid", BSSID],
        correlation_id=ASSESSMENT,
    )


def _evidence(tool: str, execution_id: str, parsed: dict, confidence: float, evidence_id=None) -> Evidence:
    evidence = Evidence.from_tool_output(
        tool_name=tool,
        capability="wireless_observation",
        evidence_type=EvidenceType.ACCESS_POINT,
        raw_output="raw output",
        parsed_data=parsed,
        parameters={"bssid": BSSID},
        interface="wlan0mon",
        confidence=confidence,
        execution_id=execution_id,
        raw_command=f"{tool} --bssid {BSSID}",
    )
    if evidence_id:
        evidence.id = evidence_id
    return evidence


def pipeline(observations):
    """Run ``(execution_id, tool, parsed_data, confidence[, evidence_id])`` tuples
    through the real Evidence Engine and World Model applier."""
    scope = AssessmentScope(authorized_bssids=[BSSID])
    state = AssessmentState(scope=scope)
    engine = EvidenceEngine(scope)
    applier = WorldModelApplier()
    requests = []
    for observation in observations:
        execution_id, tool, parsed, confidence = observation[:4]
        evidence_id = observation[4] if len(observation) > 4 else None
        result = engine.process(
            _execution(execution_id, tool),
            [_evidence(tool, execution_id, parsed, confidence, evidence_id)],
            action_id=f"action-{execution_id}",
            scope=scope,
        )
        applier.apply_evidence(state, result.evidence_set, result.evidences)
        requests.extend(result.verification_requests)
    return state, requests


def judge(state, requests):
    """Verify every open request and return the outcomes."""
    verifier = VerificationEngine()
    outcomes = [verifier.verify(request, state) for request in requests]
    assert all(outcome is not None for outcome in outcomes), "a request had no resolvable subject"
    return outcomes


def ap_record(bssid=BSSID, encryption=("WEP",), **extra):
    parsed = {"bssid": bssid, "ssid": "Office", "encryption": list(encryption)}
    parsed.update(extra)
    return parsed


EQUAL_STRENGTH = [
    ("e1", "airodump-ng", ap_record(encryption=["WPA2"]), ConfidenceLevel.HIGH),
    ("e2", "iw", ap_record(encryption=["WEP"]), ConfidenceLevel.HIGH),
]


# ------------------------------------------------------- the World Model preserves


def test_both_contradictory_observations_are_preserved():
    """The foundation. `_gather` reads `state.evidences`, so if the earlier
    observation were dropped here the contradiction would never be seen."""
    state, _ = pipeline(EQUAL_STRENGTH)

    assert len(state.evidences) == 2
    ids = {evidence.id for evidence in state.evidences}
    assert len(ids) == 2, "the two observations collapsed onto one record"

    by_tool = {evidence.source.tool_name: evidence for evidence in state.evidences}
    assert by_tool["airodump-ng"].parsed_data["encryption"] == ["WPA2"]
    assert by_tool["iw"].parsed_data["encryption"] == ["WEP"]


def test_the_entity_accumulates_the_disagreement_instead_of_overwriting():
    """`AccessPoint.encryption` is a list precisely so both values survive. A single
    string here would make the later scan silently replace the earlier one."""
    state, _ = pipeline(EQUAL_STRENGTH)
    access_point = state.world_model.access_points[BSSID]

    assert access_point.encryption == ["WPA2", "WEP"], (
        f"encryption was {access_point.encryption}; both observed values must survive "
        "in observation order"
    )
    assert len(access_point.evidence_ids) == 2, "the entity lost track of one observation"
    assert set(access_point.evidence_ids) == {evidence.id for evidence in state.evidences}


def test_a_time_varying_measurement_takes_the_latest_value_but_keeps_the_history():
    """Channel and signal genuinely change between scans, so latest-wins is correct
    for the entity - but the observations behind it must still both exist, or the
    change is indistinguishable from an overwrite."""
    state, _ = pipeline(
        [
            ("e1", "airodump-ng", ap_record(channel=6, signal=-40), ConfidenceLevel.HIGH),
            ("e2", "airodump-ng", ap_record(channel=11, signal=-80), ConfidenceLevel.HIGH),
        ]
    )
    access_point = state.world_model.access_points[BSSID]

    assert access_point.channel == 11
    assert access_point.signal_strength == -80
    assert len(state.evidences) == 2, "the superseded observation was dropped, not superseded"
    channels = sorted(evidence.parsed_data["channel"] for evidence in state.evidences)
    assert channels == [6, 11], "the earlier channel reading is gone from the record"


def test_a_duplicate_delivery_is_stored_once_and_not_counted_twice():
    """Deduplication is by evidence id, not by subject - the distinction that keeps a
    redelivered observation from inflating confidence while still allowing two real
    observations about the same AP to coexist."""
    state, requests = pipeline(
        [
            ("e1", "airodump-ng", ap_record(), ConfidenceLevel.HIGH, "fixed-evidence-id"),
            ("e2", "kismet", ap_record(), ConfidenceLevel.HIGH, "fixed-evidence-id"),
        ]
    )
    assert len(state.evidences) == 1

    outcomes = judge(state, requests)
    result = outcomes[0].result
    # One observation at HIGH, not two noisy-OR'd into false confidence.
    assert result.confidence == pytest.approx(ConfidenceLevel.HIGH)
    assert result.status == VerificationStatus.SUPPORTED
    assert result.independent_sources == ["airodump-ng"]


# --------------------------------------------------- the Verification Engine judges


def test_an_equal_strength_contradiction_is_contradicted():
    """Neither side wins, so the framework says so instead of picking one."""
    state, requests = pipeline(EQUAL_STRENGTH)
    result = judge(state, requests)[0].result

    assert result.status == VerificationStatus.CONTRADICTED
    assert len(result.supporting_evidence) == 1
    assert len(result.contradicting_evidence) == 1
    # Halved, not left at the supporting side's confidence.
    assert result.confidence == pytest.approx(ConfidenceLevel.HIGH / 2.0)
    assert result.confidence < ConfidenceLevel.HIGH


def test_the_contradiction_details_name_the_disagreeing_observation():
    """A reader must be able to see *why*, not only that the claim was blocked."""
    state, requests = pipeline(EQUAL_STRENGTH)
    result = judge(state, requests)[0].result

    contradiction = result.conclusion.details["contradiction"]
    assert len(contradiction) == 1
    entry = contradiction[0]
    assert entry["tool"] == "airodump-ng"
    assert entry["observed"] == ["WPA2"]
    assert entry["evidence_id"] in {evidence.id for evidence in state.evidences}
    assert entry["timestamp"], "the disagreeing observation is undated"

    assert result.conclusion.details["supporting_count"] == 1
    assert result.conclusion.details["contradicting_count"] == 1


def test_a_contradiction_outweighing_the_claim_refutes_it():
    state, requests = pipeline(
        [
            ("e1", "iw", ap_record(), ConfidenceLevel.LOW),
            ("e2", "airodump-ng", ap_record(encryption=["WPA2"]), ConfidenceLevel.HIGH),
            ("e3", "kismet", ap_record(encryption=["WPA2"]), ConfidenceLevel.HIGH),
        ]
    )
    result = judge(state, requests)[0].result

    assert result.status == VerificationStatus.REFUTED
    assert len(result.supporting_evidence) == 1
    assert len(result.contradicting_evidence) == 2
    # The refutation is only reached once the margin is cleared; assert the margins
    # are what the engine documents rather than trusting the outcome alone.
    support = noisy_or([ConfidenceLevel.LOW])
    contradiction = noisy_or([ConfidenceLevel.HIGH, ConfidenceLevel.HIGH])
    assert contradiction >= support + REFUTE_MARGIN


def test_a_weaker_contradiction_is_recorded_but_does_not_block_the_claim():
    """Contradicting evidence that loses still appears in the result. Discarding it
    would leave the record looking unanimous."""
    state, requests = pipeline(
        [
            ("e1", "iw", ap_record(), ConfidenceLevel.HIGH),
            ("e2", "kismet", ap_record(), ConfidenceLevel.HIGH),
            ("e3", "airodump-ng", ap_record(encryption=["WPA2"]), ConfidenceLevel.LOW),
        ]
    )
    outcome = judge(state, requests)[0]
    result = outcome.result

    assert result.status == VerificationStatus.VERIFIED
    assert len(result.contradicting_evidence) == 1, "the losing contradiction was discarded"
    assert any("weaker than supporting" in note for note in outcome.notes)


def test_a_contradiction_within_tolerance_is_not_called_a_verdict():
    """The tolerance band is what separates 'these disagree' from 'one of them is
    wrong'. Inside it the engine must decline to conclude."""
    state, requests = pipeline(EQUAL_STRENGTH)
    result = judge(state, requests)[0].result

    support = result.conclusion.details["aggregated_support_confidence"]
    contradiction = result.conclusion.details["aggregated_contradiction_confidence"]
    assert abs(support - contradiction) <= CONTRADICT_TOLERANCE
    assert contradiction < support + REFUTE_MARGIN
    assert result.status == VerificationStatus.CONTRADICTED


# ------------------------------------------------------------- what happens next


def test_a_contradiction_produces_requests_for_more_evidence():
    """The engine never executes; it asks the Decision Engine to plan. A
    contradiction resolved by fiat would be a fabricated conclusion."""
    state, requests = pipeline(EQUAL_STRENGTH)
    outcome = judge(state, requests)[0]

    assert outcome.needs_more_evidence
    assert outcome.action_requests
    for action in outcome.action_requests:
        assert isinstance(action, ActionRequest)
        assert action.capability, "the request does not name a capability to run"
    assert any("additional observation required" in note for note in outcome.notes)


def test_two_observations_from_one_tool_are_one_source_not_two():
    """The anti-fabrication guard: agreement between two runs of the same scanner is
    not corroboration, and must not reach `verified`."""
    state, requests = pipeline(
        [
            ("e1", "airodump-ng", ap_record(), ConfidenceLevel.HIGH),
            ("e2", "airodump-ng", ap_record(), ConfidenceLevel.HIGH),
        ]
    )
    result = judge(state, requests)[0].result

    assert result.independent_sources == ["airodump-ng"]
    assert result.status == VerificationStatus.SUPPORTED
    assert result.status != VerificationStatus.VERIFIED


def test_two_independent_tools_agreeing_reaches_verified():
    """Positive control. Without it, the tests above would also pass in a pipeline
    that simply never verifies anything."""
    state, requests = pipeline(
        [
            ("e1", "airodump-ng", ap_record(), ConfidenceLevel.HIGH),
            ("e2", "kismet", ap_record(), ConfidenceLevel.HIGH),
        ]
    )
    result = judge(state, requests)[0].result

    assert result.status == VerificationStatus.VERIFIED
    assert sorted(result.independent_sources) == ["airodump-ng", "kismet"]
    assert not result.contradicting_evidence
    assert result.confidence == pytest.approx(noisy_or([ConfidenceLevel.HIGH, ConfidenceLevel.HIGH]))


def test_a_contradiction_never_promotes_a_finding():
    """End to end: applying a contradicted verification result must not leave a
    finding marked confirmed."""
    from wifi_framework.core.models.finding import (
        Finding,
        FindingCategory,
        FindingSeverity,
        FindingStatus,
    )

    state, requests = pipeline(EQUAL_STRENGTH)
    outcome = judge(state, requests)[0]

    finding = Finding(
        title="WEP encryption in use",
        description="access point advertises WEP",
        category=FindingCategory.ENCRYPTION,
        severity=FindingSeverity.HIGH,
        evidence_ids=[evidence.id for evidence in state.evidences],
        affected_assets=[BSSID],
    )
    state.findings.append(finding)

    WorldModelApplier().apply_verification(state, outcome.result)

    assert finding.status not in (FindingStatus.CONFIRMED, FindingStatus.VERIFIED), (
        f"a contradicted claim was promoted to {finding.status}"
    )
    assert finding.status == FindingStatus.UNRESOLVED, (
        "a contradiction should leave the finding unresolved, not silently supported"
    )
    history = (finding.details or {}).get("verification_history") or []
    assert history, "the finding kept no record of the verification that blocked it"
    assert history[-1]["status"] == VerificationStatus.CONTRADICTED
