"""
Tests for the inter-engine data contracts.

These tests pin the guarantees other subsystems rely on: envelope completeness, version
negotiation, forward compatibility, deterministic digests, and the semantic rules that stop a
failed execution being reported as a success or a single observation being reported as verified.
"""
from __future__ import annotations

from datetime import datetime, timezone

import os
import subprocess
import sys
from pathlib import Path

import pytest

from wifi_framework.contracts import (
    CONTRACTS,
    SCHEMA_VERSIONS,
    ActionObjective,
    ActionOrigin,
    ActionReason,
    ActionRequest,
    ActionValidationResult,
    ArtifactRef,
    Claim,
    ClaimType,
    ContractEnvelope,
    ContractValidationError,
    DecisionProposal,
    EngineId,
    EntityRef,
    EvidenceRequirement,
    EvidenceSet,
    ExecutionFailure,
    ExecutionOutcomeCost,
    ExecutionResult,
    ExecutionStatus,
    ExperienceRecord,
    ActionOutcome,
    FailureCategory,
    Observation,
    ParserRef,
    PlanningContext,
    Provenance,
    TargetType,
    ToolRef,
    UnknownContractSchema,
    UnsupportedContractVersion,
    ValidationLevel,
    ValidationStatus,
    VerificationConclusion,
    VerificationMethod,
    VerificationRequest,
    VerificationResult,
    VerificationStatus,
    WorldState,
    build_default_registry,
    get_contract_registry,
    message_digest,
    parse_timestamp,
)

ASSESSMENT = "11111111-1111-4111-8111-111111111111"


def _action_request(**overrides) -> ActionRequest:
    kwargs = dict(
        assessment_id=ASSESSMENT,
        action_id="action-1",
        capability="wireless_observation",
        implementation="airodump-ng",
        objective=ActionObjective.RESOLVE_INFORMATION_GAP,
        target=EntityRef(type=TargetType.ACCESS_POINT.value, id="AA:BB:CC:DD:EE:FF"),
        reason=ActionReason(information_gaps=["gap-1"], summary="no access points observed"),
    )
    kwargs.update(overrides)
    return ActionRequest(**kwargs)


# --------------------------------------------------------------------- envelope


def test_envelope_carries_all_required_metadata():
    request = _action_request()
    envelope = request.envelope()
    assert isinstance(envelope, ContractEnvelope)
    assert envelope.schema == "action-request"
    assert envelope.version == "1.0"
    assert envelope.message_id
    assert envelope.assessment_id == ASSESSMENT
    assert envelope.source_engine == EngineId.DECISION.value
    assert envelope.correlation_id
    # ISO-8601 with an explicit offset.
    assert parse_timestamp(envelope.timestamp).tzinfo is not None


def test_assessment_id_is_mandatory():
    with pytest.raises(ContractValidationError):
        ActionRequest(assessment_id="", action_id="a", capability="wireless_observation")


def test_source_engine_defaults_to_declared_producer():
    assert _action_request().source_engine == EngineId.DECISION.value
    assert WorldState(
        assessment_id=ASSESSMENT, phase="initializing", scope={}, last_updated="2026-01-01T00:00:00+00:00"
    ).source_engine == EngineId.WORLD_MODEL.value


def test_naive_timestamp_rejected():
    message = _action_request().to_message()
    message["timestamp"] = "2026-09-16T12:00:00"
    with pytest.raises(ContractValidationError, match="UTC offset"):
        ActionRequest.parse(message)


def test_zulu_timestamp_accepted_and_normalised():
    message = _action_request().to_message()
    message["timestamp"] = "2026-09-16T12:00:00Z"
    parsed = ActionRequest.parse(message)
    assert parsed.timestamp.utcoffset().total_seconds() == 0


# ------------------------------------------------------------------- wire forms


def test_both_wire_forms_round_trip_identically():
    request = _action_request()
    from_enveloped = ActionRequest.parse(request.to_message())
    from_flat = ActionRequest.parse(request.to_dict())
    assert from_enveloped.to_dict() == request.to_dict()
    assert from_flat.to_dict() == request.to_dict()


def test_enveloped_form_nests_payload():
    message = _action_request().to_message()
    assert set(message) == {
        "schema",
        "version",
        "message_id",
        "assessment_id",
        "timestamp",
        "source_engine",
        "correlation_id",
        "payload",
    }
    assert message["payload"]["capability"] == "wireless_observation"


def test_schema_mismatch_is_rejected():
    message = _action_request().to_message()
    with pytest.raises(ContractValidationError, match="schema mismatch"):
        EvidenceSet.parse(message)


def test_typed_nested_fields_survive_round_trip():
    request = _action_request()
    parsed = ActionRequest.parse(request.to_message())
    assert isinstance(parsed.target, EntityRef)
    assert parsed.target.id == "AA:BB:CC:DD:EE:FF"
    assert isinstance(parsed.reason, ActionReason)
    assert parsed.reason.information_gaps == ["gap-1"]


# --------------------------------------------------------------------- versioning


def test_all_ten_contracts_registered_at_1_0():
    assert len(CONTRACTS) == 10
    assert set(SCHEMA_VERSIONS) == {
        "world-state",
        "planning-context",
        "decision-proposal",
        "action-request",
        "action-validation-result",
        "execution-result",
        "evidence-set",
        "verification-request",
        "verification-result",
        "experience-record",
    }
    assert all(version == "1.0" for version in SCHEMA_VERSIONS.values())
    registry = get_contract_registry()
    assert set(registry.known_schemas()) == set(SCHEMA_VERSIONS)


def test_unsupported_major_version_rejected_not_guessed():
    message = _action_request().to_message()
    message["version"] = "2.0"
    with pytest.raises(UnsupportedContractVersion):
        ActionRequest.parse(message)


def test_unknown_schema_rejected():
    message = _action_request().to_message()
    message["schema"] = "action-request-typo"
    with pytest.raises(UnknownContractSchema):
        ActionRequest.parse(message, assume_schema=True)


def test_minor_version_addition_accepted_within_major():
    registry = build_default_registry()
    assert registry.is_supported("action-request", "1.9")
    assert not registry.is_supported("action-request", "2.0")


def test_unknown_optional_field_preserved_as_extension():
    message = _action_request().to_message()
    message["payload"]["future_field"] = {"nested": True}
    parsed = ActionRequest.parse(message)
    assert parsed.extensions == {"future_field": {"nested": True}}
    # ... and re-emitted, so an older consumer does not strip a newer producer's data.
    assert parsed.to_message()["payload"]["future_field"] == {"nested": True}


# ----------------------------------------------------------------------- digests


def test_digest_is_deterministic_and_content_sensitive():
    # Timestamps default to "now", so pin it: two messages that differ only in when they were
    # constructed are different messages.
    moment = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
    first = _action_request(correlation_id="c-1", message_id="m-1", timestamp=moment)
    second = _action_request(correlation_id="c-1", message_id="m-1", timestamp=moment)
    assert first.digest() == second.digest()
    # The same message survives a wire round-trip without changing identity.
    assert ActionRequest.parse(first.to_message()).digest() == first.digest()
    assert first.digest() != _action_request(
        correlation_id="c-2", message_id="m-1", timestamp=moment
    ).digest()
    assert len(first.digest()) == 64
    assert message_digest(first.to_dict()) != first.digest()  # different shape, different digest


def test_serialisation_is_stable_for_set_valued_fields():
    state = WorldState(
        assessment_id=ASSESSMENT,
        phase="wireless_observation",
        scope={},
        channels_observed=[11, 1, 6],
        last_updated="2026-09-16T00:00:00+00:00",
    )
    assert state.digest() == WorldState.parse(state.to_message()).digest()


# ------------------------------------------------------- execution-result rules


def _execution(**overrides) -> ExecutionResult:
    kwargs = dict(
        assessment_id=ASSESSMENT,
        action_id="action-1",
        execution_id="execution-1",
        capability="wireless_observation",
        implementation="airodump-ng",
        status=ExecutionStatus.SUCCESS,
        exit_code=0,
        duration_ms=1200,
        tool=ToolRef(name="airodump-ng", version="1.7"),
    )
    kwargs.update(overrides)
    return ExecutionResult(**kwargs)


def test_successful_execution_is_valid():
    result = _execution()
    assert result.validate([ValidationLevel.STRUCTURAL, ValidationLevel.SEMANTIC]).ok


def test_failed_execution_must_carry_structured_failure():
    result = _execution(status=ExecutionStatus.FAILED)
    validation = result.validate([ValidationLevel.STRUCTURAL, ValidationLevel.SEMANTIC])
    assert not validation.ok
    assert "must carry a structured failure record" in validation.error_messages[0]


def test_success_must_not_carry_failure():
    result = _execution(
        status=ExecutionStatus.SUCCESS,
        failure=ExecutionFailure(code="x", category=FailureCategory.TOOL_ERROR, message="boom"),
    )
    validation = result.validate([ValidationLevel.SEMANTIC])
    assert not validation.ok
    assert any(issue.code == "success_with_failure" for issue in validation.issues)


def test_never_executed_status_must_not_claim_exit_code():
    result = _execution(
        status=ExecutionStatus.UNSUPPORTED,
        exit_code=127,
        failure=ExecutionFailure(
            code=FailureCategory.TOOL_NOT_FOUND,
            category=FailureCategory.TOOL_NOT_FOUND,
            message="not installed",
        ),
    )
    validation = result.validate([ValidationLevel.SEMANTIC])
    assert any(issue.code == "exit_code_without_execution" for issue in validation.issues)


def test_executed_status_requires_exit_code():
    result = _execution(status=ExecutionStatus.FAILED, exit_code=None, failure=ExecutionFailure(
        code="tool_error", category=FailureCategory.TOOL_ERROR, message="failed"))
    validation = result.validate([ValidationLevel.SEMANTIC])
    assert any(issue.code == "missing_exit_code" for issue in validation.issues)


def test_timeout_with_observations_is_partial_not_failed():
    result = _execution(
        status=ExecutionStatus.PARTIAL,
        exit_code=124,
        failure=ExecutionFailure(
            code=FailureCategory.TIMEOUT,
            category=FailureCategory.TIMEOUT,
            message="stopped at timeout after 12 observations",
            retriable=True,
        ),
    )
    assert result.validate([ValidationLevel.SEMANTIC]).ok
    assert result.executed
    assert not result.succeeded


def test_all_specified_execution_states_are_modelled():
    assert set(ExecutionStatus.ALL) == {
        "accepted",
        "running",
        "success",
        "partial",
        "failed",
        "timeout",
        "cancelled",
        "unsupported",
        "rejected",
    }


def test_artifacts_are_referenced_not_inlined():
    artifact = ArtifactRef(id="artifact-1", kind="stdout", sha256="ab" * 32, bytes=10)
    result = _execution(artifacts=[artifact], stdout_artifact="artifact-1")
    parsed = ExecutionResult.parse(result.to_message())
    assert isinstance(parsed.artifacts[0], ArtifactRef)
    assert parsed.artifact("artifact-1").sha256 == "ab" * 32
    assert parsed.artifacts_of_kind("stdout") == [parsed.artifacts[0]]


# ---------------------------------------------------- verification-result rules


def _verification(**overrides) -> VerificationResult:
    kwargs = dict(
        assessment_id=ASSESSMENT,
        verification_id="verification-1",
        status=VerificationStatus.SUPPORTED,
        subject_id="AA:BB:CC:DD:EE:FF",
        confidence=0.8,
        supporting_evidence=["evidence-1"],
        conclusion=VerificationConclusion(state=VerificationStatus.SUPPORTED, details={"reason": "single source"}),
        method=VerificationMethod.CONFIDENCE_AGGREGATION,
        independent_sources=["airodump-ng"],
        required_confidence=0.75,
    )
    kwargs.update(overrides)
    return VerificationResult(**kwargs)


def test_verified_requires_two_independent_sources():
    result = _verification(
        status=VerificationStatus.VERIFIED,
        conclusion=VerificationConclusion(state=VerificationStatus.VERIFIED),
        independent_sources=["airodump-ng"],
        confidence=0.95,
    )
    validation = result.validate([ValidationLevel.SEMANTIC])
    assert any(issue.code == "verified_without_independence" for issue in validation.issues)


def test_verified_with_two_sources_is_valid():
    result = _verification(
        status=VerificationStatus.VERIFIED,
        conclusion=VerificationConclusion(state=VerificationStatus.VERIFIED),
        independent_sources=["airodump-ng", "tshark"],
        supporting_evidence=["evidence-1", "evidence-2"],
        confidence=0.95,
        required_confidence=0.9,
        method=VerificationMethod.MULTI_TOOL_CORRELATION,
    )
    assert result.validate([ValidationLevel.STRUCTURAL, ValidationLevel.SEMANTIC]).ok


def test_verified_below_required_confidence_rejected():
    result = _verification(
        status=VerificationStatus.VERIFIED,
        conclusion=VerificationConclusion(state=VerificationStatus.VERIFIED),
        independent_sources=["a", "b"],
        confidence=0.5,
        required_confidence=0.9,
    )
    assert any(
        issue.code == "confidence_below_threshold"
        for issue in result.validate([ValidationLevel.SEMANTIC]).issues
    )


def test_unresolved_must_state_what_is_missing():
    result = _verification(
        status=VerificationStatus.UNRESOLVED,
        conclusion=VerificationConclusion(state=VerificationStatus.UNRESOLVED),
    )
    assert any(
        issue.code == "missing_required_evidence"
        for issue in result.validate([ValidationLevel.SEMANTIC]).issues
    )
    resolved = _verification(
        status=VerificationStatus.UNRESOLVED,
        conclusion=VerificationConclusion(state=VerificationStatus.UNRESOLVED),
        required_evidence=[EvidenceRequirement(observation_type="wps_observation", subject_id="AA:BB")],
    )
    assert resolved.validate([ValidationLevel.SEMANTIC]).ok
    assert resolved.needs_more_evidence


def test_refuted_must_cite_contradicting_evidence():
    result = _verification(
        status=VerificationStatus.REFUTED,
        conclusion=VerificationConclusion(state=VerificationStatus.REFUTED),
    )
    assert any(
        issue.code == "missing_contradiction"
        for issue in result.validate([ValidationLevel.SEMANTIC]).issues
    )


def test_conclusion_state_must_match_status():
    result = _verification(conclusion=VerificationConclusion(state=VerificationStatus.VERIFIED))
    assert any(
        issue.code == "conclusion_mismatch"
        for issue in result.validate([ValidationLevel.SEMANTIC]).issues
    )


def test_all_specified_verification_states_are_modelled():
    assert set(VerificationStatus.ALL) == {
        "verified",
        "supported",
        "unresolved",
        "contradicted",
        "refuted",
        "stale",
    }


# ------------------------------------------------------- verification request


def test_verification_request_round_trip_and_validation():
    request = VerificationRequest(
        assessment_id=ASSESSMENT,
        verification_id="verification-1",
        subject=EntityRef(type=TargetType.ACCESS_POINT.value, id="AA:BB:CC:DD:EE:FF"),
        claim=Claim(type=ClaimType.WPS_STATE, description="WPS enabled", attribute="wps_enabled", expected_value=True),
        supporting_evidence=["evidence-1"],
        required_confidence=0.85,
        min_independent_sources=2,
    )
    assert request.validate().ok
    parsed = VerificationRequest.parse(request.to_message())
    assert isinstance(parsed.claim, Claim)
    assert parsed.claim.expected_value is True
    assert parsed.subject.id == "AA:BB:CC:DD:EE:FF"


def test_out_of_range_confidence_rejected():
    with pytest.raises(ContractValidationError):
        VerificationRequest.parse(
            VerificationRequest(
                assessment_id=ASSESSMENT,
                verification_id="v",
                subject=EntityRef(type=TargetType.ACCESS_POINT.value, id="AA"),
                claim=Claim(type=ClaimType.WPS_STATE, description="d"),
                required_confidence=1.5,
            ).to_message()
        )


def test_verification_action_request_uses_the_action_contract():
    """Specification section 9: the verification follow-up is an ordinary action-request."""
    request = ActionRequest.for_verification(
        assessment_id=ASSESSMENT,
        action_id="action-9",
        verification_id="verification-1",
        capability="wps_discovery",
        target=EntityRef(type=TargetType.ACCESS_POINT.value, id="AA:BB:CC:DD:EE:FF"),
        summary="need a second WPS observation",
    )
    assert isinstance(request, ActionRequest)
    assert request.SCHEMA == "action-request"
    assert request.objective == ActionObjective.RESOLVE_VERIFICATION_REQUIREMENT
    assert request.origin == ActionOrigin.VERIFICATION
    assert request.verification_id == "verification-1"
    assert request.verification_required
    assert request.validate().ok


# ------------------------------------------------------------ evidence-set rules


def test_observation_requires_provenance_to_its_execution():
    evidence_set = EvidenceSet(
        assessment_id=ASSESSMENT,
        action_id="action-1",
        execution_id="execution-1",
        observations=[Observation(id="obs-1", type="access_point", data={"bssid": "AA:BB"})],
    )
    issues = evidence_set.structural_issues()
    assert any(issue.code == "missing_provenance" for issue in issues)


def test_evidence_set_with_provenance_is_valid():
    evidence_set = EvidenceSet(
        assessment_id=ASSESSMENT,
        action_id="action-1",
        execution_id="execution-1",
        observations=[
            Observation(
                id="obs-1",
                type="access_point",
                subject_id="AA:BB:CC:DD:EE:FF",
                confidence=0.85,
                data={"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "TestNet"},
                provenance=Provenance(execution_id="execution-1", action_id="action-1", tool="airodump-ng"),
                tags=["in_scope"],
            )
        ],
        artifacts=[ArtifactRef(id="artifact-1", kind="stdout", bytes=5)],
        parser=ParserRef(name="airodump-csv", version="1.0"),
    )
    assert evidence_set.validate().ok
    parsed = EvidenceSet.parse(evidence_set.to_message())
    assert isinstance(parsed.observations[0], Observation)
    assert parsed.observations[0].in_scope is True
    assert parsed.tools() == ["airodump-ng"]
    assert parsed.subjects() == ["AA:BB:CC:DD:EE:FF"]
    assert parsed.by_subject("AA:BB:CC:DD:EE:FF")[0].id == "obs-1"


def test_declared_parse_issues_are_preserved():
    evidence_set = EvidenceSet(
        assessment_id=ASSESSMENT,
        action_id="action-1",
        execution_id="execution-1",
        parse_issues=["3 malformed CSV rows skipped"],
        incomplete=True,
    )
    assert EvidenceSet.parse(evidence_set.to_message()).parse_issues == ["3 malformed CSV rows skipped"]


# ------------------------------------------------------------------- action rules


def test_action_request_requires_action_id_capability_and_objective():
    with pytest.raises(ContractValidationError):
        ActionRequest.parse(
            ActionRequest(assessment_id=ASSESSMENT, action_id="", capability="x").to_message()
        )


def test_unknown_objective_rejected():
    message = _action_request().to_message()
    message["payload"]["objective"] = "run_everything"
    with pytest.raises(ContractValidationError, match="objective"):
        ActionRequest.parse(message)


def test_immutable_requests_produce_new_objects():
    request = _action_request()
    prepared = request.with_parameters({"channel": 6}, interface="wlan0mon")
    assert prepared.parameters == {"channel": 6}
    assert prepared.interface == "wlan0mon"
    assert prepared.prepared is True
    # Original untouched: messages are immutable records.
    assert request.parameters == {}
    assert request.prepared is False
    assert prepared.message_id == request.message_id
    assert prepared.action_id == request.action_id


def test_resolution_does_not_mark_request_prepared():
    request = _action_request(implementation=None)
    resolved = request.with_resolution(implementation="airodump-ng", interface="wlan0mon")
    assert resolved.implementation == "airodump-ng"
    assert resolved.prepared is False


def test_correlation_rebinding_preserves_identity():
    request = _action_request()
    rebound = request.with_correlation("correlation-2")
    assert rebound.correlation_id == "correlation-2"
    assert rebound.action_id == request.action_id
    assert request.correlation_id != "correlation-2"


def test_validation_result_requires_reason_when_rejected():
    with pytest.raises(ContractValidationError, match="structured reason"):
        ActionValidationResult.parse(
            ActionValidationResult(
                assessment_id=ASSESSMENT, action_id="a", status=ValidationStatus.REJECTED
            ).to_message()
        )


# --------------------------------------------------------------------- AI layer


def test_decision_proposal_cannot_express_a_command():
    proposal = DecisionProposal(
        assessment_id=ASSESSMENT, capability="wireless_observation", reasoning_summary="observe first"
    )
    message = proposal.to_message()
    message["payload"]["command"] = "airodump-ng -i wlan0mon"
    with pytest.raises(ContractValidationError, match="cannot invoke an operating-system shell"):
        DecisionProposal.parse(message)


def test_proposal_converts_to_a_validated_action_request():
    proposal = DecisionProposal(
        assessment_id=ASSESSMENT,
        capability="wireless_observation",
        target=EntityRef(type=TargetType.ACCESS_POINT.value, id="AA:BB:CC:DD:EE:FF"),
        parameters={"channel": 6},
        reasoning_summary="no APs observed yet",
        confidence=0.78,
        information_gaps=["gap-1"],
    )
    request = proposal.to_action_request(action_id="action-7")
    assert isinstance(request, ActionRequest)
    assert request.origin == ActionOrigin.AI_PROPOSAL
    assert request.parameters == {"channel": 6}
    assert request.reason.summary == "no APs observed yet"
    assert request.validate().ok


def test_planning_context_is_a_constrained_projection():
    context = PlanningContext(
        assessment_id=ASSESSMENT,
        objective={"description": "assess TestNet"},
        relevant_state={"phase": "wireless_observation"},
        information_gaps=[{"id": "gap-1", "type": "wireless_observation"}],
        available_capabilities=[{"name": "airodump-ng", "available": True}],
        constraints={"may_not_invoke_shell": True},
    )
    assert context.validate().ok
    assert context.capability_names() == ["airodump-ng"]
    parsed = PlanningContext.parse(context.to_message())
    assert parsed.constraints["may_not_invoke_shell"] is True


# ------------------------------------------------------------------- experience


def test_experience_record_requires_state_digests():
    record = ExperienceRecord(
        assessment_id=ASSESSMENT,
        record_id="record-1",
        state_before="short",
        state_after="0" * 64,
        action={},
        execution={},
        outcome=ActionOutcome(information_gain=0.5, useful=True),
    )
    assert any(issue.code == "invalid_digest" for issue in record.structural_issues())


def test_experience_record_round_trip():
    execution = _execution(
        artifacts=[ArtifactRef(id="artifact-1", kind="stdout", bytes=4096)],
    )
    record = ExperienceRecord(
        assessment_id=ASSESSMENT,
        record_id="record-1",
        state_before="a" * 64,
        state_after="b" * 64,
        action=_action_request().payload(),
        execution=execution.payload(),
        observations=[{"id": "obs-1", "type": "access_point"}],
        verification=_verification().payload(),
        outcome=ActionOutcome(
            information_gain=0.42,
            useful=True,
            new_observations=3,
            gaps_closed=["gap-1"],
            cost=ExecutionOutcomeCost.from_execution(execution),
        ),
        capability="wireless_observation",
        tool="airodump-ng",
        action_id="action-1",
        execution_id="execution-1",
    )
    assert record.validate().ok
    parsed = ExperienceRecord.parse(record.to_message())
    assert parsed.outcome.information_gain == 0.42
    assert parsed.outcome.cost.duration_ms == 1200
    assert parsed.outcome.cost.bytes_collected == 4096
    assert parsed.outcome.cost.tool_invocations == 1
    assert parsed.state_changed
    assert parsed.outcome.gaps_closed == ["gap-1"]
    assert parsed.action_id == "action-1"


def test_information_gain_is_bounded():
    record = ExperienceRecord(
        assessment_id=ASSESSMENT,
        record_id="r",
        state_before="a" * 64,
        state_after="b" * 64,
        action={},
        execution={},
        outcome=ActionOutcome(information_gain=1.5),
    )
    assert any(issue.code == "out_of_range" for issue in record.structural_issues())


# ---------------------------------------------------------------- digest determinism
#
# `digest()` is documented as a deterministic SHA-256 and feeds the experience
# record's state_before/state_after. A digest that varies between processes reports
# a state transition that never happened.


def test_an_unserialisable_value_does_not_make_the_digest_vary_between_processes():
    """Cross-process, because the bug is invisible within one.

    CPython reuses freed addresses, so two instances in the same process digest
    identically and the defect only appears across runs. `default=str` in the
    encoder produced `<Opaque object at 0x7f...>`, which changed every process.
    """
    code = (
        "from wifi_framework.contracts.base import message_digest\n"
        "class Opaque:\n"
        "    pass\n"
        "print(message_digest({'x': Opaque()}))\n"
    )

    # The child must be able to import the package however the parent found it -
    # installed into site-packages or running from a source checkout. Without this
    # the child dies with ModuleNotFoundError and the test reports a digest problem
    # that is really an environment problem.
    import wifi_framework

    package_parent = str(Path(wifi_framework.__file__).resolve().parent.parent)
    child_env = dict(os.environ)
    existing = child_env.get("PYTHONPATH", "")
    child_env["PYTHONPATH"] = package_parent + (os.pathsep + existing if existing else "")

    digests = set()
    for _ in range(3):
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, timeout=90, env=child_env
        )
        assert proc.returncode == 0, proc.stderr
        digests.add(proc.stdout.strip())

    assert len(digests) == 1, f"digest varied between processes: {digests}"


def test_to_jsonable_substitutes_a_stable_name_for_a_default_object_repr():
    from wifi_framework.contracts.common import to_jsonable

    class Opaque:
        pass

    result = to_jsonable(Opaque())

    assert "0x" not in result, f"memory address leaked into serialisation: {result!r}"
    assert "Opaque" in result


def test_to_jsonable_preserves_a_meaningful_str():
    """The substitution must not discard a deliberately stable representation."""
    from wifi_framework.contracts.common import to_jsonable

    class Named:
        def __str__(self) -> str:
            return "stable-value"

    assert to_jsonable(Named()) == "stable-value"


def test_a_contract_digest_is_unchanged_by_repeated_serialisation():
    from wifi_framework.contracts.world_state import WorldState

    state = WorldState(
        assessment_id="DIGEST-TEST",
        phase="wireless_observation",
        scope={},
        channels_observed=[1, 6, 11],
        last_updated="2026-01-01T00:00:00+00:00",
    )

    assert state.digest() == state.digest()
    assert state.digest() == WorldState.parse(state.to_message()).digest()
