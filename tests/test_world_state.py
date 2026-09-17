"""
Tests for the World Model side of the contract layer.

``WorldStatePublisher`` projects the authoritative state into the ``world-state`` contract the
Decision Engine plans from; ``WorldModelApplier`` is the only writer that folds ``evidence-set``,
``execution-record`` and ``verification-result`` contracts back into it. Together they are what
makes the loop's "observe, model, re-evaluate" step explicit instead of implicit.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from wifi_framework.contracts import (
    ArtifactRef,
    Claim,
    ClaimType,
    EngineId,
    EntityRef,
    EvidenceSet,
    ExecutionResult,
    ExecutionStatus,
    Observation,
    ParserRef,
    Provenance,
    TargetType,
    ToolRef,
    VerificationConclusion,
    VerificationMethod,
    VerificationResult,
    VerificationStatus,
    WorldState,
)
from wifi_framework.contracts.envelope import utc_now
from wifi_framework.core.execution.registry import CapabilityRegistry
from wifi_framework.core.models.assessment_state import (
    AssessmentPhase,
    AssessmentState,
    ExecutionRecord,
    InterfaceInfo,
)
from wifi_framework.core.models.evidence import ConfidenceLevel, Evidence, EvidenceType
from wifi_framework.core.models.finding import Finding, FindingCategory, FindingSeverity, FindingStatus
from wifi_framework.core.models.scope import AssessmentScope
from wifi_framework.core.models.world_model import AccessPoint, NetworkHost, WirelessClient
from wifi_framework.core.world import (
    DEFAULT_STALENESS_SECONDS,
    WorldModelApplier,
    WorldStatePublisher,
    uncertainty_id,
)
from wifi_framework.tools.registry_loader import load_all_adapters

ASSESSMENT = "55555555-5555-4555-8555-555555555555"
IN_SCOPE = "AA:BB:CC:DD:EE:FF"
OUT_OF_SCOPE = "11:22:33:44:55:66"


@pytest.fixture(scope="module")
def registry() -> CapabilityRegistry:
    loaded = CapabilityRegistry()
    load_all_adapters(loaded)
    return loaded


def ap_evidence(
    bssid: str,
    *,
    tool: str = "airodump-ng",
    ssid: str = "TestNet",
    age_seconds: float = 0.0,
    evidence_type: EvidenceType = EvidenceType.ACCESS_POINT,
    data: dict | None = None,
) -> Evidence:
    parsed = {"bssid": bssid, "ssid": ssid, "channel": 6, "encryption": ["WPA2"]}
    parsed.update(data or {})
    item = Evidence.from_tool_output(
        tool_name=tool,
        capability="wireless_observation",
        evidence_type=evidence_type,
        raw_output="raw",
        parsed_data=parsed,
        parameters={},
        interface="wlan0mon",
        confidence=ConfidenceLevel.HIGH,
        execution_id="execution-1",
        raw_command=f"{tool} -i wlan0mon",
    )
    if age_seconds:
        item.timestamp = utc_now() - timedelta(seconds=age_seconds)
    return item


def populated_state(scope: AssessmentScope | None = None, registry: CapabilityRegistry | None = None):
    """A state that has already observed one AP, one client, one host and run one action."""
    state = AssessmentState(scope=scope or AssessmentScope(authorized_bssids=[IN_SCOPE]))
    state.transition_phase(AssessmentPhase.WIRELESS_OBSERVATION)

    evidence = ap_evidence(IN_SCOPE)
    state.add_evidence(evidence)
    state.world_model.access_points[IN_SCOPE] = AccessPoint(
        bssid=IN_SCOPE,
        ssid="TestNet",
        channel=6,
        encryption=["WPA2"],
        wps_enabled=True,
        first_seen=evidence.timestamp,
        last_seen=evidence.timestamp,
        evidence_ids=[evidence.id],
    )
    state.world_model.clients["CC:DD:EE:FF:00:11"] = WirelessClient(
        mac="CC:DD:EE:FF:00:11", associated_bssid=IN_SCOPE, last_seen=evidence.timestamp
    )
    state.world_model.network_hosts["10.0.0.5"] = NetworkHost(ip="10.0.0.5", hostname="printer")
    state.world_model.channels_observed.update({1, 6, 11})
    state.world_model.ssids_observed.update({"TestNet", "AlphaNet"})

    state.interfaces["wlan0mon"] = InterfaceInfo(
        name="wlan0mon", type="wifi", driver="mac80211", supports_monitor=True, is_up=True, channel=6
    )
    if registry is not None:
        state.available_capabilities["airodump-ng"] = registry.get_metadata("airodump-ng")
        state.unavailable_capabilities["reaver"] = "Tool 'reaver' not found"

    state.execution_history.append(
        ExecutionRecord(
            id="execution-1",
            capability_name="wireless_observation",
            tool_binary="airodump-ng",
            interface="wlan0mon",
            exit_code=0,
            duration_seconds=12.5,
            success=True,
            evidence_ids=[evidence.id],
            action_id="action-1",
            correlation_id=ASSESSMENT,
            status=ExecutionStatus.SUCCESS,
            artifact_ids=["artifact-1"],
        )
    )
    state.uncertainties.append(
        {
            "type": "wps_assessment",
            "priority": 7,
            "description": "WPS state needs a second observation source",
            "required_capabilities": ["wash", "reaver"],
            "context": {"bssids": [IN_SCOPE]},
        }
    )
    state.uncertainties.append(
        {"type": "wireless_observation", "priority": 9, "description": "coverage incomplete", "context": {}}
    )
    return state, evidence


# --------------------------------------------------------------------- publishing


def test_published_state_is_a_valid_contract(registry):
    state, _ = populated_state(registry=registry)
    published = WorldStatePublisher().publish(state)
    assert isinstance(published, WorldState)
    assert published.source_engine == EngineId.WORLD_MODEL.value
    assert published.assessment_id == state.id
    assert published.phase == "wireless_observation"
    validation = published.validate()
    assert validation.ok, validation.error_messages
    assert WorldState.parse(published.to_message()).to_dict() == published.to_dict()


def test_revision_increases_and_is_carried_on_the_message(registry):
    state, _ = populated_state(registry=registry)
    publisher = WorldStatePublisher()
    assert publisher.revision == 0
    first = publisher.publish(state)
    second = publisher.publish(state)
    assert (first.revision, second.revision) == (1, 2)
    assert publisher.revision == 2


def test_correlation_id_defaults_to_the_assessment_and_can_be_overridden(registry):
    state, _ = populated_state(registry=registry)
    publisher = WorldStatePublisher()
    assert publisher.publish(state).correlation_id == state.id
    assert publisher.publish(state, correlation_id="action-1").correlation_id == "action-1"


def test_scope_and_objective_are_projected_for_the_decision_engine(registry):
    scope = AssessmentScope(
        authorized_ssids=["TestNet"], authorized_bssids=[IN_SCOPE], description="assess TestNet", strict_mode=True
    )
    state, _ = populated_state(scope=scope, registry=registry)
    published = WorldStatePublisher().publish(state)
    assert published.scope["authorized_bssids"] == [IN_SCOPE]
    assert published.objective["description"] == "assess TestNet"
    assert published.objective["strict_mode"] is True


def test_observed_assets_are_projected_with_their_evidence(registry):
    state, evidence = populated_state(registry=registry)
    published = WorldStatePublisher().publish(state)

    access_point = published.access_points[0]
    assert access_point.id == IN_SCOPE
    assert access_point.ssid == "TestNet"
    assert access_point.wps_enabled is True
    assert access_point.evidence_ids == [evidence.id]
    assert access_point.evidence_tools == ["airodump-ng"]
    assert published.clients[0].associated_ap_id == IN_SCOPE
    assert published.networks[0].hosts[0].id == "10.0.0.5"


def test_assets_are_tagged_against_scope(registry):
    scope = AssessmentScope(authorized_bssids=[IN_SCOPE])
    state, evidence = populated_state(scope=scope, registry=registry)
    state.world_model.access_points[OUT_OF_SCOPE] = AccessPoint(bssid=OUT_OF_SCOPE, ssid="Neighbour")
    published = WorldStatePublisher().publish(state)
    flags = {item.id: item.in_scope for item in published.access_points}
    assert flags[IN_SCOPE] is True
    assert flags[OUT_OF_SCOPE] is False


def test_stale_observations_are_flagged_not_silently_trusted(registry):
    scope = AssessmentScope(authorized_bssids=[IN_SCOPE])
    state, _ = populated_state(scope=scope, registry=registry)
    # Last seen well outside the freshness window.
    state.world_model.access_points[IN_SCOPE].last_seen = utc_now() - timedelta(seconds=3600)
    published = WorldStatePublisher(staleness_seconds=600).publish(state)
    assert published.access_points[0].stale is True

    fresh = populated_state(scope=scope, registry=registry)[0]
    assert WorldStatePublisher(staleness_seconds=600).publish(fresh).access_points[0].stale is False


def test_staleness_window_is_declared_on_the_message(registry):
    state, _ = populated_state(registry=registry)
    assert WorldStatePublisher(staleness_seconds=45).publish(state).staleness_seconds == 45


def test_non_positive_staleness_window_is_refused():
    with pytest.raises(ValueError):
        WorldStatePublisher(staleness_seconds=0)


def test_open_questions_and_conclusions_are_kept_separate(registry):
    state, evidence = populated_state(registry=registry)
    open_finding = Finding(
        title="WPS enabled",
        description="d",
        category=FindingCategory.WPS,
        severity=FindingSeverity.HIGH,
        status=FindingStatus.SUPPORTED,
        evidence_ids=[evidence.id],
        affected_assets=[IN_SCOPE],
    )
    closed_finding = Finding(
        title="WEP in use",
        description="d",
        category=FindingCategory.ENCRYPTION,
        severity=FindingSeverity.CRITICAL,
        status=FindingStatus.VERIFIED,
        evidence_ids=[evidence.id],
        affected_assets=[IN_SCOPE],
    )
    state.findings.extend([open_finding, closed_finding])

    published = WorldStatePublisher().publish(state)
    assert [item.id for item in published.hypotheses] == [open_finding.id]
    assert [item.id for item in published.findings] == [closed_finding.id]
    assert published.hypotheses[0].status == FindingStatus.SUPPORTED.value
    assert published.hypotheses[0].evidence_tools == ["airodump-ng"]


def test_uncertainties_are_published_with_stable_ids_and_priority_order(registry):
    state, _ = populated_state(registry=registry)
    first = WorldStatePublisher().publish(state)
    second = WorldStatePublisher().publish(state)

    assert [gap.priority for gap in first.uncertainties] == [9, 7]
    # Same gap, same id - so the Decision Engine can tell a persistent gap from a new one.
    assert [gap.id for gap in first.uncertainties] == [gap.id for gap in second.uncertainties]
    wps_gap = next(gap for gap in first.uncertainties if gap.type == "wps_assessment")
    assert wps_gap.subject_ids == [IN_SCOPE]
    assert wps_gap.required_capabilities == ["wash", "reaver"]
    assert wps_gap.id == uncertainty_id("wps_assessment", [IN_SCOPE])


def test_uncertainty_id_depends_on_type_and_subjects_only():
    assert uncertainty_id("wps_assessment", [IN_SCOPE]) == uncertainty_id("wps_assessment", [IN_SCOPE])
    # Order and duplicates must not change the identity of the gap.
    assert uncertainty_id("wps_assessment", [IN_SCOPE, OUT_OF_SCOPE]) == uncertainty_id(
        "wps_assessment", [OUT_OF_SCOPE, IN_SCOPE, IN_SCOPE]
    )
    assert uncertainty_id("wps_assessment", [IN_SCOPE]) != uncertainty_id("wps_assessment", [OUT_OF_SCOPE])
    assert uncertainty_id("wps_assessment", [IN_SCOPE]) != uncertainty_id("encryption_assessment", [IN_SCOPE])
    assert uncertainty_id("wps_assessment", []).startswith("gap-")


def test_capability_availability_is_published_with_reasons(registry):
    state, _ = populated_state(registry=registry)
    published = WorldStatePublisher().publish(state)
    by_name = {item.name: item for item in published.capabilities}

    available = by_name["airodump-ng"]
    assert available.available is True
    assert available.reason is None
    assert available.category == "wireless_observation"
    assert available.tool_binary == "airodump-ng"
    assert available.interface_required is True
    assert "monitor_mode" in available.interface_capabilities
    assert "access_points" in available.outputs
    assert available.invasive is False

    # An unavailable capability stays visible with its reason: it is a fact about the environment.
    unavailable = by_name["reaver"]
    assert unavailable.available is False
    assert unavailable.reason == "Tool 'reaver' not found"


def test_execution_history_is_projected_with_its_correlation_chain(registry):
    state, _ = populated_state(registry=registry)
    published = WorldStatePublisher().publish(state)
    record = published.execution_summary[0]
    assert record["execution_id"] == "execution-1"
    assert record["action_id"] == "action-1"
    assert record["correlation_id"] == ASSESSMENT
    assert record["status"] == ExecutionStatus.SUCCESS
    assert record["evidence_count"] == 1
    assert record["duration_seconds"] == 12.5


def test_planner_hints_are_kept_separate_from_facts(registry):
    state, _ = populated_state(registry=registry)
    state.extra["experience_scores"] = {"wireless_observation/airodump-ng": 0.8}
    state.extra["blocked_capabilities"] = {"reaver": {"reason": "tool_not_found", "until_iteration": 9}}
    published = WorldStatePublisher().publish(state)
    assert published.planner_hints["experience_scores"] == {"wireless_observation/airodump-ng": 0.8}
    assert published.planner_hints["blocked_capabilities"]["reaver"]["reason"] == "tool_not_found"


def test_observations_and_evidence_index_expose_provenance(registry):
    state, evidence = populated_state(registry=registry)
    published = WorldStatePublisher().publish(state)
    observation = published.observations[0]
    assert observation.id == evidence.id
    assert observation.type == "access_point"
    assert observation.subject_id == IN_SCOPE
    assert observation.confidence == float(ConfidenceLevel.HIGH)
    assert published.evidence[0]["tool"] == "airodump-ng"


def test_observed_channels_and_ssids_are_sorted(registry):
    state, _ = populated_state(registry=registry)
    published = WorldStatePublisher().publish(state)
    assert published.channels_observed == [1, 6, 11]
    assert published.ssids_observed == ["AlphaNet", "TestNet"]


# ---------------------------------------------------------------------- applying


def make_evidence_set(
    evidences: list[Evidence],
    *,
    action_id: str = "action-1",
    execution_id: str = "execution-1",
    in_scope: bool = True,
    parse_issues: list[str] | None = None,
    incomplete: bool = False,
) -> EvidenceSet:
    return EvidenceSet(
        assessment_id=ASSESSMENT,
        action_id=action_id,
        execution_id=execution_id,
        correlation_id=ASSESSMENT,
        capability="wireless_observation",
        tool="airodump-ng",
        parser=ParserRef(name="airodump-csv", version="1.0"),
        artifacts=[ArtifactRef(id="artifact-1", kind="stdout", bytes=128)],
        observations=[
            Observation(
                id=item.id,
                type=item.evidence_type.value,
                subject_id=(item.parsed_data or {}).get("bssid"),
                subject_type="access_point",
                confidence=float(item.confidence),
                data=dict(item.parsed_data or {}),
                provenance=Provenance(
                    execution_id=execution_id,
                    action_id=action_id,
                    assessment_id=ASSESSMENT,
                    correlation_id=ASSESSMENT,
                    tool=item.source.tool_name,
                ),
                tags=["in_scope" if in_scope else "out_of_scope"],
            )
            for item in evidences
        ],
        parse_issues=list(parse_issues or []),
        incomplete=incomplete,
    )


def test_apply_evidence_binds_the_correlation_chain_onto_the_record():
    state = AssessmentState(scope=AssessmentScope(authorized_bssids=[IN_SCOPE]))
    item = ap_evidence(IN_SCOPE)
    applier = WorldModelApplier()

    report = applier.apply_evidence(state, make_evidence_set([item]), [item])

    assert report.accepted == 1
    assert report.state_changed is True
    assert report.added_ids == [item.id]
    applied = state.evidences[0]
    assert applied.action_id == "action-1"
    assert applied.correlation_id == ASSESSMENT
    assert applied.execution_id == "execution-1"
    assert "in_scope" in applied.tags


def test_apply_evidence_refuses_records_the_contract_did_not_declare():
    """Nothing may enter the World Model that the evidence-set does not account for."""
    state = AssessmentState(scope=AssessmentScope())
    declared = ap_evidence(IN_SCOPE)
    undeclared = ap_evidence(OUT_OF_SCOPE)
    applier = WorldModelApplier()

    report = applier.apply_evidence(state, make_evidence_set([declared]), [declared, undeclared])

    assert report.accepted == 1
    assert report.skipped == [undeclared.id]
    assert any("not declared in the evidence-set" in note for note in report.notes)
    assert [item.id for item in state.evidences] == [declared.id]


def test_apply_evidence_is_idempotent():
    state = AssessmentState(scope=AssessmentScope())
    item = ap_evidence(IN_SCOPE)
    evidence_set = make_evidence_set([item])
    applier = WorldModelApplier()

    applier.apply_evidence(state, evidence_set, [item])
    second = applier.apply_evidence(state, evidence_set, [item])

    assert second.accepted == 0
    assert second.skipped == [item.id]
    assert second.state_changed is False
    assert len(state.evidences) == 1


def test_apply_evidence_carries_declared_extraction_problems_forward():
    state = AssessmentState(scope=AssessmentScope())
    item = ap_evidence(IN_SCOPE)
    report = WorldModelApplier().apply_evidence(
        state,
        make_evidence_set([item], parse_issues=["3 malformed CSV rows skipped"], incomplete=True),
        [item],
    )
    assert any("parse_issue: 3 malformed CSV rows skipped" in note for note in report.notes)
    assert any("marked incomplete" in note for note in report.notes)


def test_apply_evidence_updates_the_world_model_index():
    state = AssessmentState(scope=AssessmentScope(authorized_bssids=[IN_SCOPE]))
    item = ap_evidence(IN_SCOPE, ssid="TestNet", data={"wps_enabled": True})
    WorldModelApplier().apply_evidence(state, make_evidence_set([item]), [item])
    assert IN_SCOPE in state.world_model.access_points
    assert state.world_model.access_points[IN_SCOPE].ssid == "TestNet"


def test_apply_execution_appends_and_deduplicates():
    state = AssessmentState(scope=AssessmentScope())
    record = ExecutionRecord(
        id="execution-9",
        capability_name="wireless_observation",
        tool_binary="airodump-ng",
        success=True,
        exit_code=0,
        action_id="action-9",
        status=ExecutionStatus.SUCCESS,
    )
    applier = WorldModelApplier()

    first = applier.apply_execution(state, record)
    assert first.accepted == 1
    assert first.state_changed is True

    second = applier.apply_execution(state, record)
    assert second.accepted == 0
    assert second.state_changed is False
    assert len(state.execution_history) == 1


def test_apply_execution_keeps_failures_visible():
    """History is append-only: an attempt that failed still belongs in the audit trail."""
    state = AssessmentState(scope=AssessmentScope())
    failed = ExecutionRecord(
        id="execution-failed",
        capability_name="wireless_observation",
        tool_binary="airodump-ng",
        success=False,
        exit_code=1,
        status=ExecutionStatus.FAILED,
        failure_reason="interface busy",
    )
    WorldModelApplier().apply_execution(state, failed)
    assert state.execution_history[0].status == ExecutionStatus.FAILED
    assert state.execution_history[0].failure_reason == "interface busy"


@pytest.mark.parametrize(
    "verification_status,expected_finding_status",
    [
        (VerificationStatus.VERIFIED, FindingStatus.VERIFIED),
        (VerificationStatus.SUPPORTED, FindingStatus.SUPPORTED),
        (VerificationStatus.REFUTED, FindingStatus.REFUTED),
        (VerificationStatus.CONTRADICTED, FindingStatus.UNRESOLVED),
        (VerificationStatus.UNRESOLVED, FindingStatus.UNRESOLVED),
        (VerificationStatus.STALE, FindingStatus.UNRESOLVED),
    ],
)
def test_apply_verification_drives_the_finding_lifecycle(verification_status, expected_finding_status):
    state = AssessmentState(scope=AssessmentScope(authorized_bssids=[IN_SCOPE]))
    finding = Finding(
        title="WPS enabled",
        description="d",
        category=FindingCategory.WPS,
        severity=FindingSeverity.HIGH,
        status=FindingStatus.HYPOTHESIS,
        evidence_ids=["evidence-1", "evidence-2"],
        affected_assets=[IN_SCOPE],
    )
    state.findings.append(finding)

    result = VerificationResult(
        assessment_id=state.id,
        verification_id="verification-1",
        status=verification_status,
        subject_id=IN_SCOPE,
        hypothesis_id=finding.id,
        confidence=0.96,
        supporting_evidence=["evidence-1", "evidence-2"],
        independent_sources=["wash", "airodump-ng"],
        conclusion=VerificationConclusion(state=verification_status, details={"reason": "test"}),
        method=VerificationMethod.MULTI_TOOL_CORRELATION,
        required_confidence=0.85,
        required_evidence=[{"observation_type": "wps_observation", "subject_id": IN_SCOPE}]
        if verification_status in (VerificationStatus.UNRESOLVED, VerificationStatus.STALE)
        else [],
        contradicting_evidence=["evidence-2"] if verification_status == VerificationStatus.REFUTED else [],
    )

    report = WorldModelApplier().apply_verification(state, result)

    assert report.accepted == 1
    assert report.updated_ids == [finding.id]
    assert finding.status == expected_finding_status
    history = finding.details["verification_history"]
    assert history[-1]["verification_id"] == "verification-1"
    assert history[-1]["status"] == verification_status


def test_verified_finding_records_the_corroborating_evidence():
    state = AssessmentState(scope=AssessmentScope(authorized_bssids=[IN_SCOPE]))
    finding = Finding(
        title="WPS enabled",
        description="d",
        category=FindingCategory.WPS,
        severity=FindingSeverity.HIGH,
        status=FindingStatus.SUPPORTED,
        evidence_ids=["evidence-1", "evidence-2"],
        affected_assets=[IN_SCOPE],
    )
    state.findings.append(finding)
    result = VerificationResult(
        assessment_id=state.id,
        verification_id="verification-1",
        status=VerificationStatus.VERIFIED,
        subject_id=IN_SCOPE,
        hypothesis_id=finding.id,
        confidence=0.96,
        supporting_evidence=["evidence-1", "evidence-2"],
        independent_sources=["wash", "airodump-ng"],
        conclusion=VerificationConclusion(state=VerificationStatus.VERIFIED),
        method=VerificationMethod.MULTI_TOOL_CORRELATION,
        required_confidence=0.85,
    )
    WorldModelApplier().apply_verification(state, result)
    assert finding.status == FindingStatus.VERIFIED
    assert finding.verification_evidence_ids
    assert finding.verified_at is not None


def test_apply_verification_refuses_to_touch_unknown_findings():
    state = AssessmentState(scope=AssessmentScope())
    result = VerificationResult(
        assessment_id=state.id,
        verification_id="verification-1",
        status=VerificationStatus.VERIFIED,
        subject_id="99:99:99:99:99:99",
        hypothesis_id="finding-that-does-not-exist",
        confidence=0.99,
        supporting_evidence=["evidence-1", "evidence-2"],
        independent_sources=["a", "b"],
        conclusion=VerificationConclusion(state=VerificationStatus.VERIFIED),
        required_confidence=0.85,
    )
    report = WorldModelApplier().apply_verification(state, result)
    assert report.rejected == 1
    assert report.accepted == 0
    assert report.state_changed is False
    assert any("does not exist" in note for note in report.notes)


def test_apply_report_is_serialisable():
    state = AssessmentState(scope=AssessmentScope())
    item = ap_evidence(IN_SCOPE)
    report = WorldModelApplier().apply_evidence(state, make_evidence_set([item]), [item])
    as_dict = report.to_dict()
    assert as_dict["contract_schema"] == "evidence-set"
    assert as_dict["accepted"] == 1
    assert as_dict["state_changed"] is True
    assert set(as_dict) == {
        "contract_schema",
        "accepted",
        "rejected",
        "added_ids",
        "updated_ids",
        "skipped",
        "notes",
        "state_changed",
    }


# --------------------------------------------------------------- publish/apply loop


def test_applied_evidence_becomes_visible_in_the_next_published_state():
    """The loop closes: apply, then publish, and the Decision Engine sees the new observation."""
    state = AssessmentState(scope=AssessmentScope(authorized_bssids=[IN_SCOPE]))
    item = ap_evidence(IN_SCOPE, data={"wps_enabled": True})
    applier = WorldModelApplier()
    publisher = WorldStatePublisher()

    before = publisher.publish(state)
    assert before.access_points == []

    applier.apply_evidence(state, make_evidence_set([item]), [item])
    after = publisher.publish(state)

    assert [ap.id for ap in after.access_points] == [IN_SCOPE]
    assert after.access_points[0].wps_enabled is True
    assert after.evidence[0]["id"] == item.id
    assert after.revision == before.revision + 1
    assert after.validate().ok
