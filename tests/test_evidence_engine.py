"""
Tests for the Evidence Engine.

The engine's job is to turn raw tool output into attributed, scoped observations and to decide
what still needs verification. These tests assert the guarantees the rest of the framework
depends on: nothing is invented, provenance is complete, out-of-scope observations cannot drive
conclusions, and a claim is never marked verified on a single source.
"""
from __future__ import annotations

import pytest

from wifi_framework.contracts import (
    ArtifactRef,
    ClaimType,
    EngineId,
    EvidenceSet,
    ExecutionFailure,
    ExecutionResult,
    ExecutionStatus,
    FailureCategory,
    InterfaceRef,
    ToolRef,
    VerificationRequest,
)
from wifi_framework.core.evidence import EvidenceEngine
from wifi_framework.core.models.evidence import ConfidenceLevel, Evidence, EvidenceType
from wifi_framework.core.models.scope import AssessmentScope

ASSESSMENT = "33333333-3333-4333-8333-333333333333"
ACTION = "action-evidence-1"
EXECUTION = "execution-evidence-1"
IN_SCOPE = "AA:BB:CC:DD:EE:FF"
OUT_OF_SCOPE = "11:22:33:44:55:66"


def make_execution(
    *,
    status: str = ExecutionStatus.SUCCESS,
    exit_code: int | None = 0,
    capability: str = "wireless_observation",
    tool: str = "airodump-ng",
    artifacts: list[ArtifactRef] | None = None,
    failure: ExecutionFailure | None = None,
    interface: str | None = "wlan0mon",
) -> ExecutionResult:
    return ExecutionResult(
        assessment_id=ASSESSMENT,
        action_id=ACTION,
        execution_id=EXECUTION,
        capability=capability,
        implementation=tool,
        status=status,
        exit_code=exit_code,
        duration_ms=1500,
        tool=ToolRef(name=tool, version="1.7"),
        interface=InterfaceRef(name=interface) if interface else None,
        artifacts=artifacts or [],
        stdout_artifact=artifacts[0].id if artifacts else None,
        command=[tool, "--bssid", IN_SCOPE],
        failure=failure,
        correlation_id=ASSESSMENT,
    )


def make_evidence(
    evidence_type: EvidenceType,
    parsed_data: dict,
    *,
    tool: str = "airodump-ng",
    capability: str = "wireless_observation",
    confidence: float = ConfidenceLevel.HIGH,
    interface: str | None = "wlan0mon",
    tags: list[str] | None = None,
) -> Evidence:
    evidence = Evidence.from_tool_output(
        tool_name=tool,
        capability=capability,
        evidence_type=evidence_type,
        raw_output="raw output text",
        parsed_data=parsed_data,
        parameters={"bssid": IN_SCOPE},
        interface=interface,
        confidence=confidence,
        execution_id=EXECUTION,
        raw_command=f"{tool} --bssid {IN_SCOPE}",
    )
    if tags:
        evidence.tags = list(tags)
    return evidence


def process(engine: EvidenceEngine, execution: ExecutionResult, evidences: list[Evidence], **kwargs):
    return engine.process(execution, evidences, **kwargs)


# --------------------------------------------------------------------- provenance


def test_observation_carries_a_complete_provenance_chain():
    engine = EvidenceEngine()
    artifact = ArtifactRef(id="artifact-1", kind="stdout", sha256="cd" * 32, bytes=256)
    execution = make_execution(artifacts=[artifact])
    evidence = make_evidence(EvidenceType.ACCESS_POINT, {"bssid": IN_SCOPE, "ssid": "TestNet"})

    result = process(engine, execution, [evidence])
    observation = result.evidence_set.observations[0]

    assert observation.provenance.execution_id == EXECUTION
    assert observation.provenance.action_id == ACTION
    assert observation.provenance.assessment_id == ASSESSMENT
    assert observation.provenance.correlation_id == ASSESSMENT
    assert observation.provenance.tool == "airodump-ng"
    assert observation.provenance.interface == "wlan0mon"
    assert observation.provenance.raw_command.startswith("airodump-ng")
    # The observation is derived from the artifacts that actually contain the tool output.
    assert observation.provenance.derived_from == ["artifact-1"]


def test_observation_id_matches_the_evidence_it_came_from():
    engine = EvidenceEngine()
    evidence = make_evidence(EvidenceType.ACCESS_POINT, {"bssid": IN_SCOPE})
    result = process(engine, make_execution(), [evidence])
    assert result.evidence_set.observations[0].id == evidence.id
    # The model-layer objects correspond one-to-one with the observations.
    assert [item.id for item in result.evidences] == [obs.id for obs in result.evidence_set.observations]


def test_bssid_subject_ids_are_normalised_to_upper_case():
    engine = EvidenceEngine()
    result = process(engine, make_execution(), [
        make_evidence(EvidenceType.ACCESS_POINT, {"bssid": "aa:bb:cc:dd:ee:ff", "ssid": "TestNet"})
    ])
    assert result.evidence_set.observations[0].subject_id == IN_SCOPE
    assert result.evidence_set.observations[0].subject_type == "access_point"


def test_evidence_set_declares_its_producer_and_parser():
    engine = EvidenceEngine(parser_name="airodump-csv", parser_version="2.1")
    result = process(engine, make_execution(), [
        make_evidence(EvidenceType.ACCESS_POINT, {"bssid": IN_SCOPE})
    ])
    evidence_set = result.evidence_set
    assert evidence_set.source_engine == EngineId.EVIDENCE.value
    assert evidence_set.parser.name == "airodump-csv"
    assert evidence_set.parser.version == "2.1"
    assert evidence_set.action_id == ACTION
    assert evidence_set.execution_id == EXECUTION
    assert evidence_set.capability == "wireless_observation"
    assert evidence_set.tool == "airodump-ng"
    assert evidence_set.validate().ok
    assert EvidenceSet.parse(evidence_set.to_message()).to_dict() == evidence_set.to_dict()


def test_explicit_action_id_overrides_the_execution_default():
    engine = EvidenceEngine()
    result = engine.process(make_execution(), [make_evidence(EvidenceType.ACCESS_POINT, {"bssid": IN_SCOPE})],
                            action_id="action-override")
    assert result.evidence_set.action_id == "action-override"
    assert result.evidence_set.observations[0].provenance.action_id == "action-override"


# -------------------------------------------------------------------------- scope


def test_in_scope_and_out_of_scope_observations_are_tagged():
    engine = EvidenceEngine(AssessmentScope(authorized_bssids=[IN_SCOPE]))
    result = process(engine, make_execution(), [
        make_evidence(EvidenceType.ACCESS_POINT, {"bssid": IN_SCOPE, "ssid": "TestNet"}),
        make_evidence(EvidenceType.ACCESS_POINT, {"bssid": OUT_OF_SCOPE, "ssid": "Neighbour"}),
    ])
    tags = {obs.subject_id: obs.tags for obs in result.evidence_set.observations}
    assert "in_scope" in tags[IN_SCOPE]
    assert "out_of_scope" in tags[OUT_OF_SCOPE]


def test_existing_scope_tag_is_not_overwritten():
    engine = EvidenceEngine(AssessmentScope(authorized_bssids=[IN_SCOPE]))
    result = process(engine, make_execution(), [
        make_evidence(EvidenceType.ACCESS_POINT, {"bssid": OUT_OF_SCOPE}, tags=["in_scope"])
    ])
    assert result.evidence_set.observations[0].tags == ["in_scope"]


def test_network_observations_are_scoped_by_ip():
    engine = EvidenceEngine(AssessmentScope(authorized_networks=["10.0.0.0/24"]))
    result = process(engine, make_execution(tool="nmap", capability="network_discovery"), [
        make_evidence(EvidenceType.NETWORK_HOST, {"ip": "10.0.0.5"}, tool="nmap", interface=None),
        make_evidence(EvidenceType.NETWORK_HOST, {"ip": "192.168.1.1"}, tool="nmap", interface=None),
    ])
    tags = {obs.subject_id: obs.tags for obs in result.evidence_set.observations}
    assert "in_scope" in tags["10.0.0.5"]
    assert "out_of_scope" in tags["192.168.1.1"]


def test_out_of_scope_observation_generates_no_verification_request():
    """Evidence about an unauthorised asset must not drive assessment conclusions."""
    engine = EvidenceEngine(AssessmentScope(authorized_bssids=[IN_SCOPE]))
    result = process(engine, make_execution(tool="wash", capability="wps_assessment"), [
        make_evidence(
            EvidenceType.WPS,
            {"bssid": OUT_OF_SCOPE, "wps_enabled": True},
            tool="wash",
            capability="wps_assessment",
        )
    ])
    assert result.evidence_set.observations[0].tags == ["out_of_scope"]
    assert result.verification_requests == []


# ------------------------------------------------------------------ no fabrication


def test_unattributable_evidence_is_dropped_and_reported():
    engine = EvidenceEngine()
    evidence = make_evidence(EvidenceType.GENERIC, {}, interface=None)
    result = process(engine, make_execution(), [evidence])
    assert result.evidence_set.observations == []
    assert result.dropped == [evidence.id]
    assert result.evidence_set.incomplete
    assert any("could not be attributed" in issue for issue in result.evidence_set.parse_issues)


def test_evidence_without_parsed_data_is_recorded_as_unstructured_not_dropped():
    engine = EvidenceEngine()
    # No parsed fields, but an interface gives it a subject, so it is kept and flagged.
    result = process(engine, make_execution(), [make_evidence(EvidenceType.INTERFACE, {})])
    observation = result.evidence_set.observations[0]
    assert observation.partial is True
    assert observation.subject_id == "wlan0mon"
    assert any("no parsed data" in issue for issue in result.evidence_set.parse_issues)


def test_no_claim_is_invented_when_the_data_does_not_imply_one():
    engine = EvidenceEngine()
    result = process(engine, make_execution(), [
        make_evidence(EvidenceType.ACCESS_POINT, {"bssid": IN_SCOPE, "ssid": "TestNet", "channel": 6})
    ])
    # Nothing about encryption or WPS was observed, so nothing may be claimed about them.
    assert result.verification_requests == []


# ------------------------------------------------------------------ verification


def test_wps_observation_requests_independent_confirmation():
    engine = EvidenceEngine()
    result = process(engine, make_execution(tool="wash", capability="wps_assessment"), [
        make_evidence(
            EvidenceType.WPS,
            {"bssid": IN_SCOPE, "wps_enabled": True},
            tool="wash",
            capability="wps_assessment",
        )
    ])
    assert len(result.verification_requests) == 1
    request = result.verification_requests[0]
    assert isinstance(request, VerificationRequest)
    assert request.claim.type == ClaimType.WPS_STATE
    assert request.claim.attribute == "wps_enabled"
    assert request.claim.expected_value is True
    assert request.subject.id == IN_SCOPE
    assert request.required_confidence == 0.85
    assert request.min_independent_sources == 2
    assert request.supporting_evidence
    assert request.action_id == ACTION
    assert request.execution_id == EXECUTION
    assert {requirement.type for requirement in request.verification_requirements} == {
        "independent_source",
        "freshness",
        "minimum_confidence",
    }
    assert request.validate().ok


def test_wps_observation_without_state_implies_nothing():
    engine = EvidenceEngine()
    result = process(engine, make_execution(tool="wash", capability="wps_assessment"), [
        make_evidence(EvidenceType.WPS, {"bssid": IN_SCOPE}, tool="wash")
    ])
    assert result.verification_requests == []


@pytest.mark.parametrize(
    "evidence_type,expected_claim,expected_confidence",
    [
        (EvidenceType.VULNERABILITY, ClaimType.VULNERABILITY_PRESENT, 0.95),
        (EvidenceType.CREDENTIAL, ClaimType.CREDENTIAL_RECOVERED, 0.95),
        (EvidenceType.HANDSHAKE, ClaimType.HANDSHAKE_CAPTURED, 0.90),
    ],
)
def test_high_stakes_observations_require_independent_confirmation(
    evidence_type, expected_claim, expected_confidence
):
    engine = EvidenceEngine()
    result = process(engine, make_execution(tool="hashcat", capability="credential_assessment"), [
        make_evidence(evidence_type, {"bssid": IN_SCOPE, "detail": "x"}, tool="hashcat")
    ])
    assert len(result.verification_requests) == 1
    request = result.verification_requests[0]
    assert request.claim.type == expected_claim
    assert request.required_confidence == expected_confidence
    assert request.min_independent_sources == 2


def test_weak_encryption_raises_an_encryption_state_claim():
    engine = EvidenceEngine()
    result = process(engine, make_execution(), [
        make_evidence(EvidenceType.ACCESS_POINT, {"bssid": IN_SCOPE, "encryption": ["WEP"]})
    ])
    claims = {request.claim.type: request.claim for request in result.verification_requests}
    assert ClaimType.ENCRYPTION_STATE in claims
    assert claims[ClaimType.ENCRYPTION_STATE].expected_value == ["WEP"]


def test_strong_encryption_raises_no_claim():
    engine = EvidenceEngine()
    result = process(engine, make_execution(), [
        make_evidence(EvidenceType.ACCESS_POINT, {"bssid": IN_SCOPE, "encryption": ["WPA2", "AES"]})
    ])
    assert result.verification_requests == []


def test_hidden_ssid_raises_an_asset_attribute_claim():
    engine = EvidenceEngine()
    result = process(engine, make_execution(), [
        make_evidence(EvidenceType.ACCESS_POINT, {"bssid": IN_SCOPE, "is_hidden": True})
    ])
    assert [request.claim.type for request in result.verification_requests] == [ClaimType.ASSET_ATTRIBUTE]


def test_repeated_observations_reuse_one_verification_cycle():
    """Ten observations of the same WPS access point must not spawn ten verification cycles."""
    engine = EvidenceEngine()
    wash_execution = make_execution(tool="wash", capability="wps_assessment")
    wps_evidence = lambda: make_evidence(  # noqa: E731 - two identical observations, separate runs
        EvidenceType.WPS,
        {"bssid": IN_SCOPE, "wps_enabled": True},
        tool="wash",
        capability="wps_assessment",
    )
    first = process(engine, wash_execution, [wps_evidence()])
    second = process(engine, wash_execution, [wps_evidence()])
    assert len(first.verification_requests) == 1
    assert len(second.verification_requests) == 1
    assert first.verification_requests[0].verification_id == second.verification_requests[0].verification_id
    assert engine.verification_id_for(IN_SCOPE, ClaimType.WPS_STATE) == (
        first.verification_requests[0].verification_id
    )
    assert len(engine.known_verification_ids()) == 1


def test_two_claims_on_one_subject_get_separate_cycles():
    engine = EvidenceEngine()
    result = process(engine, make_execution(), [
        make_evidence(
            EvidenceType.ACCESS_POINT,
            {"bssid": IN_SCOPE, "encryption": ["WEP"], "is_hidden": True},
        )
    ])
    claim_types = {request.claim.type for request in result.verification_requests}
    assert claim_types == {ClaimType.ENCRYPTION_STATE, ClaimType.ASSET_ATTRIBUTE}
    ids = {request.verification_id for request in result.verification_requests}
    assert len(ids) == 2


# ------------------------------------------------------------------ partial output


def test_timeout_marks_observations_partial_and_incomplete():
    engine = EvidenceEngine()
    execution = make_execution(
        status=ExecutionStatus.TIMEOUT,
        exit_code=124,
        failure=ExecutionFailure(
            code=FailureCategory.TIMEOUT,
            category=FailureCategory.TIMEOUT,
            message="stopped after 30s",
            retriable=True,
        ),
    )
    result = process(engine, execution, [
        make_evidence(EvidenceType.ACCESS_POINT, {"bssid": IN_SCOPE, "ssid": "TestNet"})
    ])
    assert result.evidence_set.incomplete is True
    assert result.evidence_set.observations[0].partial is True
    assert any("timed out" in issue for issue in result.evidence_set.parse_issues)


def test_partial_execution_is_flagged():
    engine = EvidenceEngine()
    execution = make_execution(
        status=ExecutionStatus.PARTIAL,
        exit_code=124,
        failure=ExecutionFailure(
            code=FailureCategory.TIMEOUT,
            category=FailureCategory.TIMEOUT,
            message="stopped after 12 observations",
        ),
    )
    result = process(engine, execution, [
        make_evidence(EvidenceType.ACCESS_POINT, {"bssid": IN_SCOPE})
    ])
    assert result.evidence_set.incomplete is True
    assert any("partial completion" in issue for issue in result.evidence_set.parse_issues)


def test_failed_execution_notes_that_observations_come_from_a_failed_run():
    engine = EvidenceEngine()
    execution = make_execution(
        status=ExecutionStatus.FAILED,
        exit_code=1,
        failure=ExecutionFailure(
            code="tool_error", category=FailureCategory.TOOL_ERROR, message="interface busy"
        ),
    )
    result = process(engine, execution, [
        make_evidence(EvidenceType.ACCESS_POINT, {"bssid": IN_SCOPE})
    ])
    assert any("failed run" in issue for issue in result.evidence_set.parse_issues)


def test_never_executed_tool_must_produce_an_empty_set_with_an_explanation():
    engine = EvidenceEngine()
    execution = make_execution(
        status=ExecutionStatus.UNSUPPORTED,
        exit_code=None,
        tool="airodump-ng",
        failure=ExecutionFailure(
            code=FailureCategory.TOOL_NOT_FOUND,
            category=FailureCategory.TOOL_NOT_FOUND,
            message="Tool 'airodump-ng' not found",
        ),
    )
    result = process(engine, execution, [])
    assert result.evidence_set.observations == []
    assert any("never executed" in issue for issue in result.evidence_set.parse_issues)
    assert result.evidence_set.validate().ok


def test_truncated_artifact_is_disclosed():
    engine = EvidenceEngine()
    artifact = ArtifactRef(id="artifact-1", kind="stdout", bytes=10_000_000, truncated=True)
    result = process(engine, make_execution(artifacts=[artifact]), [
        make_evidence(EvidenceType.ACCESS_POINT, {"bssid": IN_SCOPE})
    ])
    assert any("truncated" in issue for issue in result.evidence_set.parse_issues)


def test_summary_reports_the_processing_outcome():
    engine = EvidenceEngine(AssessmentScope(authorized_bssids=[IN_SCOPE]))
    result = process(engine, make_execution(), [
        make_evidence(EvidenceType.ACCESS_POINT, {"bssid": IN_SCOPE, "encryption": ["WEP"]}),
        make_evidence(EvidenceType.GENERIC, {}, interface=None),
    ])
    summary = result.summary()
    assert summary["observations"] == 1
    assert summary["dropped"] and summary["incomplete"] is True
    assert summary["parse_issues"]
