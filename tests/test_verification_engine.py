"""
Tests for the Verification Engine.

These pin the framework's central honesty rule: a claim reaches ``verified`` only through
independent corroboration, insufficient evidence stays ``unresolved`` with an explicit statement
of what is missing, and contradicting evidence is surfaced rather than averaged away. The engine
never executes a tool - it returns action requests for the Decision Engine to schedule.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from wifi_framework.contracts import (
    ActionObjective,
    ActionOrigin,
    ActionRequest,
    Claim,
    ClaimType,
    EntityRef,
    EvidenceRequirement,
    TargetType,
    VerificationMethod,
    VerificationRequest,
    VerificationResult,
    VerificationStatus,
)
from wifi_framework.core.models.assessment_state import AssessmentState
from wifi_framework.core.models.evidence import ConfidenceLevel, Evidence, EvidenceType
from wifi_framework.core.models.finding import Finding, FindingCategory, FindingSeverity, FindingStatus
from wifi_framework.core.models.scope import AssessmentScope
from wifi_framework.core.verification import VerificationEngine, VerificationOutcome, noisy_or
from wifi_framework.contracts.envelope import utc_now

ASSESSMENT = "44444444-4444-4444-8444-444444444444"
SUBJECT = "AA:BB:CC:DD:EE:FF"


def evidence(
    *,
    tool: str,
    confidence: float = ConfidenceLevel.HIGH,
    data: dict | None = None,
    evidence_type: EvidenceType = EvidenceType.WPS,
    age_seconds: float = 0.0,
    interface: str | None = "wlan0mon",
) -> Evidence:
    parsed = {"bssid": SUBJECT}
    parsed.update(data or {})
    item = Evidence.from_tool_output(
        tool_name=tool,
        capability="wps_assessment",
        evidence_type=evidence_type,
        raw_output="raw",
        parsed_data=parsed,
        parameters={"bssid": SUBJECT},
        interface=interface,
        confidence=confidence,
        execution_id="execution-1",
        raw_command=f"{tool} -i {interface}",
    )
    if age_seconds:
        item.timestamp = utc_now() - timedelta(seconds=age_seconds)
    return item


def state_with(*evidences: Evidence) -> AssessmentState:
    state = AssessmentState(scope=AssessmentScope(authorized_bssids=[SUBJECT]))
    state.evidences.extend(evidences)
    return state


def wps_request(
    *,
    expected: bool = True,
    required_confidence: float = 0.85,
    min_sources: int = 2,
    max_age_seconds: int = 600,
    supporting: list[str] | None = None,
    contradicting: list[str] | None = None,
) -> VerificationRequest:
    return VerificationRequest(
        assessment_id=ASSESSMENT,
        verification_id="verification-1",
        subject=EntityRef(type=TargetType.ACCESS_POINT.value, id=SUBJECT),
        claim=Claim(
            type=ClaimType.WPS_STATE,
            description="WPS enabled on the access point",
            attribute="wps_enabled",
            expected_value=expected,
        ),
        supporting_evidence=list(supporting or []),
        contradicting_evidence=list(contradicting or []),
        required_confidence=required_confidence,
        min_independent_sources=min_sources,
        max_age_seconds=max_age_seconds,
    )


# --------------------------------------------------------------------- aggregation


def test_noisy_or_combines_independent_confidences():
    assert noisy_or([]) == 0.0
    assert noisy_or([0.7]) == 0.7
    # 1 - (0.3 * 0.3) = 0.91: independent repetition raises confidence.
    assert noisy_or([0.7, 0.7]) == 0.91
    assert noisy_or([0.9, 0.9, 0.9]) == 0.999
    # Out-of-range and unusable values are clamped or skipped, never allowed to corrupt the result.
    assert noisy_or([1.5]) == 1.0
    assert noisy_or([-0.5]) == 0.0
    assert noisy_or([0.5, None, "x"]) == 0.5


# ------------------------------------------------------------------------ verified


def test_two_independent_tools_verify_a_claim():
    engine = VerificationEngine()
    state = state_with(
        evidence(tool="wash", confidence=0.8, data={"wps_enabled": True}),
        evidence(tool="airodump-ng", confidence=0.8, data={"wps_enabled": True}),
    )
    outcome = engine.verify(wps_request(required_confidence=0.85), state)
    assert outcome is not None
    result = outcome.result
    assert result.status == VerificationStatus.VERIFIED
    assert result.method == VerificationMethod.MULTI_TOOL_CORRELATION
    # 1 - (0.2 * 0.2) = 0.96
    assert result.confidence == pytest.approx(0.96)
    assert result.independent_sources == ["airodump-ng", "wash"]
    assert outcome.needs_more_evidence is False
    assert outcome.action_requests == []


def test_one_tool_can_support_but_never_verify():
    """Specification: a single observation cannot reach 'verified', however confident it looks."""
    engine = VerificationEngine()
    state = state_with(evidence(tool="wash", confidence=0.95, data={"wps_enabled": True}))
    outcome = engine.verify(wps_request(required_confidence=0.85, min_sources=2), state)
    result = outcome.result
    assert result.status == VerificationStatus.SUPPORTED
    assert result.method == VerificationMethod.CONFIDENCE_AGGREGATION
    assert result.independent_sources == ["wash"]
    assert "only 1 independent source" in result.conclusion.details["reason"]


def test_repeating_the_same_tool_does_not_count_as_independence():
    engine = VerificationEngine()
    state = state_with(
        evidence(tool="wash", confidence=0.7, data={"wps_enabled": True}),
        evidence(tool="wash", confidence=0.7, data={"wps_enabled": True}),
    )
    outcome = engine.verify(wps_request(required_confidence=0.85), state)
    assert outcome.result.status == VerificationStatus.SUPPORTED
    assert outcome.result.method == VerificationMethod.REPEATED_OBSERVATION
    assert outcome.result.independent_sources == ["wash"]


# ---------------------------------------------------------------------- unresolved


def test_insufficient_confidence_stays_unresolved_and_says_what_is_missing():
    engine = VerificationEngine()
    state = state_with(evidence(tool="wash", confidence=0.4, data={"wps_enabled": True}))
    outcome = engine.verify(wps_request(required_confidence=0.85), state)
    result = outcome.result
    assert result.status == VerificationStatus.UNRESOLVED
    assert result.method == VerificationMethod.INSUFFICIENT_EVIDENCE
    assert result.needs_more_evidence is True
    assert result.required_evidence
    assert all(isinstance(item, EvidenceRequirement) for item in result.required_evidence)
    assert outcome.needs_more_evidence is True


def test_no_evidence_about_the_subject_is_unresolved_not_a_pass():
    engine = VerificationEngine()
    state = state_with(evidence(tool="wash", data={"bssid": "11:22:33:44:55:66", "wps_enabled": True}))
    outcome = engine.verify(wps_request(), state)
    result = outcome.result
    assert result.status == VerificationStatus.UNRESOLVED
    assert result.confidence == 0.0
    assert "no evidence about this subject" in result.conclusion.details["reason"]
    assert outcome.notes == ["no evidence found for subject"]


def test_unjudgeable_request_returns_none():
    """With neither a subject nor a hypothesis to judge, the engine declines rather than guessing."""
    engine = VerificationEngine()
    request = VerificationRequest(
        assessment_id=ASSESSMENT,
        verification_id="verification-1",
        subject=EntityRef(type=TargetType.ACCESS_POINT.value, id=""),
        claim=Claim(type=ClaimType.WPS_STATE, description="WPS enabled"),
        required_confidence=0.85,
    )
    assert engine.verify(request, state_with()) is None


def test_evidence_silent_on_the_claimed_attribute_is_neither_support_nor_contradiction():
    """An observation of the AP that says nothing about WPS must not be counted as corroboration."""
    engine = VerificationEngine()
    state = state_with(
        evidence(tool="wash", confidence=0.9, data={"wps_enabled": True}),
        evidence(tool="airodump-ng", confidence=0.9, data={"ssid": "TestNet"}),
    )
    outcome = engine.verify(wps_request(required_confidence=0.85), state)
    assert outcome.result.status == VerificationStatus.SUPPORTED
    assert outcome.result.independent_sources == ["wash"]


# -------------------------------------------------------------------- contradiction


def test_stronger_contradiction_refutes_the_claim():
    engine = VerificationEngine()
    state = state_with(
        evidence(tool="wash", confidence=0.6, data={"wps_enabled": True}),
        evidence(tool="airodump-ng", confidence=0.95, data={"wps_enabled": False}),
    )
    outcome = engine.verify(wps_request(required_confidence=0.85), state)
    result = outcome.result
    assert result.status == VerificationStatus.REFUTED
    assert result.method == VerificationMethod.CONTRADICTION_DETECTION
    assert result.contradicting_evidence
    assert result.conclusion.details["contradiction"]


def test_close_contradiction_is_contradicted_and_requests_more_evidence():
    engine = VerificationEngine()
    state = state_with(
        evidence(tool="wash", confidence=0.8, data={"wps_enabled": True}),
        evidence(tool="airodump-ng", confidence=0.78, data={"wps_enabled": False}),
    )
    outcome = engine.verify(wps_request(required_confidence=0.85), state)
    assert outcome.result.status == VerificationStatus.CONTRADICTED
    assert outcome.needs_more_evidence is True


def test_weak_contradiction_is_recorded_but_does_not_block_the_claim():
    engine = VerificationEngine()
    state = state_with(
        evidence(tool="wash", confidence=0.9, data={"wps_enabled": True}),
        evidence(tool="airodump-ng", confidence=0.9, data={"wps_enabled": True}),
        evidence(tool="horst", confidence=0.3, data={"wps_enabled": False}),
    )
    outcome = engine.verify(wps_request(required_confidence=0.85), state)
    assert outcome.result.status == VerificationStatus.VERIFIED
    assert outcome.result.contradicting_evidence
    assert any("weaker than supporting" in note for note in outcome.notes)


def test_explicitly_declared_contradicting_evidence_is_honoured():
    engine = VerificationEngine()
    supporting_item = evidence(tool="wash", confidence=0.6, data={"wps_enabled": True})
    contradicting_item = evidence(tool="airodump-ng", confidence=0.95, data={"wps_enabled": True})
    state = state_with(supporting_item, contradicting_item)
    request = wps_request(
        required_confidence=0.85,
        supporting=[supporting_item.id],
        contradicting=[contradicting_item.id],
    )
    outcome = engine.verify(request, state)
    assert outcome.result.status == VerificationStatus.REFUTED
    assert outcome.result.supporting_evidence == [supporting_item.id]


# ------------------------------------------------------------------------- freshness


def test_stale_evidence_is_not_accepted_as_current():
    engine = VerificationEngine(default_max_age_seconds=600)
    state = state_with(
        evidence(tool="wash", confidence=0.95, data={"wps_enabled": True}, age_seconds=3600),
        evidence(tool="airodump-ng", confidence=0.95, data={"wps_enabled": True}, age_seconds=3600),
    )
    outcome = engine.verify(wps_request(required_confidence=0.85), state)
    result = outcome.result
    assert result.status == VerificationStatus.STALE
    assert result.method == VerificationMethod.FRESHNESS_CHECK
    assert result.conclusion.details["newest_support_age_seconds"] > 600
    assert outcome.needs_more_evidence is True


def test_fresh_evidence_within_the_window_is_accepted():
    engine = VerificationEngine(default_max_age_seconds=600)
    state = state_with(
        evidence(tool="wash", confidence=0.9, data={"wps_enabled": True}, age_seconds=30),
        evidence(tool="airodump-ng", confidence=0.9, data={"wps_enabled": True}, age_seconds=30),
    )
    assert engine.verify(wps_request(), state).result.status == VerificationStatus.VERIFIED


def test_request_specific_freshness_window_overrides_the_default():
    engine = VerificationEngine(default_max_age_seconds=600)
    state = state_with(
        evidence(tool="wash", confidence=0.9, data={"wps_enabled": True}, age_seconds=300),
        evidence(tool="airodump-ng", confidence=0.9, data={"wps_enabled": True}, age_seconds=300),
    )
    outcome = engine.verify(wps_request(max_age_seconds=60), state)
    assert outcome.result.status == VerificationStatus.STALE


# ------------------------------------------------------------- requested follow-ups


def test_requested_actions_are_action_requests_the_engine_never_executes():
    """The Verification Engine may only ask; running a tool stays with the Execution Engine."""
    engine = VerificationEngine()
    state = state_with(evidence(tool="wash", confidence=0.4, data={"wps_enabled": True}))
    outcome = engine.verify(wps_request(required_confidence=0.85), state)
    assert outcome.action_requests
    for request in outcome.action_requests:
        assert isinstance(request, ActionRequest)
        assert request.origin == ActionOrigin.VERIFICATION
        assert request.objective == ActionObjective.RESOLVE_VERIFICATION_REQUIREMENT
        assert request.verification_id == "verification-1"
        assert request.verification_required is True
        assert request.validate().ok
        assert request.target.id == SUBJECT


def test_outcome_summary_is_json_shaped():
    engine = VerificationEngine()
    outcome = engine.verify(wps_request(), state_with(evidence(tool="wash", data={"wps_enabled": True})))
    summary = outcome.summary()
    assert summary["verification_id"] == "verification-1"
    assert summary["status"] == VerificationStatus.SUPPORTED
    assert isinstance(summary["requested_actions"], int)


# ------------------------------------------------------------------ contract shape


def test_result_is_a_valid_serialisable_contract():
    engine = VerificationEngine()
    state = state_with(
        evidence(tool="wash", confidence=0.9, data={"wps_enabled": True}),
        evidence(tool="airodump-ng", confidence=0.9, data={"wps_enabled": True}),
    )
    result = engine.verify(wps_request(), state).result
    assert isinstance(result, VerificationResult)
    assert result.subject_id == SUBJECT
    assert result.claim.type == ClaimType.WPS_STATE
    assert result.conclusion.state == result.status
    validation = result.validate()
    assert validation.ok, validation.error_messages
    assert VerificationResult.parse(result.to_message()).to_dict() == result.to_dict()


def test_unresolved_result_declares_the_evidence_it_needs():
    engine = VerificationEngine()
    result = engine.verify(
        wps_request(required_confidence=0.85),
        state_with(evidence(tool="wash", confidence=0.4, data={"wps_enabled": True})),
    ).result
    assert result.required_evidence
    assert result.validate().ok


# --------------------------------------------------------------- finding-driven use


def test_request_for_finding_derives_claim_and_severity_threshold():
    engine = VerificationEngine()
    state = state_with(evidence(tool="wash", confidence=0.9, data={"wps_enabled": True}))
    finding = Finding(
        title="WPS enabled",
        description="WPS is enabled and may allow PIN recovery",
        category=FindingCategory.WPS,
        severity=FindingSeverity.CRITICAL,
        status=FindingStatus.HYPOTHESIS,
        evidence_ids=[state.evidences[0].id],
        affected_assets=[SUBJECT],
    )
    state.findings.append(finding)
    request = engine.request_for_finding(finding, state)
    assert request.claim.type == ClaimType.WPS_STATE
    assert request.subject.type == TargetType.ACCESS_POINT.value
    assert request.subject.id == SUBJECT
    assert request.required_confidence == 0.95  # critical claims need the strongest evidence
    assert request.min_independent_sources == 2
    assert request.hypothesis_id == finding.id
    assert request.supporting_evidence == [state.evidences[0].id]


@pytest.mark.parametrize(
    "severity,expected",
    [
        (FindingSeverity.CRITICAL, 0.95),
        (FindingSeverity.HIGH, 0.90),
        (FindingSeverity.MEDIUM, 0.85),
        (FindingSeverity.LOW, 0.80),
        (FindingSeverity.INFO, 0.75),
    ],
)
def test_severity_drives_the_verification_bar(severity, expected):
    engine = VerificationEngine()
    finding = Finding(
        title="t",
        description="d",
        category=FindingCategory.ENCRYPTION,
        severity=severity,
        status=FindingStatus.HYPOTHESIS,
        affected_assets=[SUBJECT],
    )
    request = engine.request_for_finding(finding, state_with())
    assert request.required_confidence == expected


def test_asset_existence_needs_only_one_source():
    engine = VerificationEngine()
    finding = Finding(
        title="AP present",
        description="access point observed",
        category=FindingCategory.WIRELESS,
        severity=FindingSeverity.INFO,
        status=FindingStatus.HYPOTHESIS,
        affected_assets=[SUBJECT],
    )
    assert engine.request_for_finding(finding, state_with()).min_independent_sources == 1


def test_finding_without_a_wireless_asset_is_addressed_by_finding_id():
    engine = VerificationEngine()
    finding = Finding(
        title="Misconfiguration",
        description="configuration weakness",
        category=FindingCategory.CONFIGURATION,
        severity=FindingSeverity.MEDIUM,
        status=FindingStatus.HYPOTHESIS,
    )
    request = engine.request_for_finding(finding, state_with())
    assert request.subject.type == TargetType.FINDING.value
    assert request.subject.id == finding.id


def test_verify_open_findings_only_judges_open_questions():
    engine = VerificationEngine()
    corroborating = state_with(
        evidence(tool="wash", confidence=0.95, data={"wps_enabled": True}),
        evidence(tool="airodump-ng", confidence=0.95, data={"wps_enabled": True}),
    )
    open_finding = Finding(
        title="WPS enabled",
        description="d",
        category=FindingCategory.WPS,
        severity=FindingSeverity.HIGH,
        status=FindingStatus.SUPPORTED,
        evidence_ids=[item.id for item in corroborating.evidences],
        affected_assets=[SUBJECT],
    )
    closed_finding = Finding(
        title="Already verified",
        description="d",
        category=FindingCategory.WPS,
        severity=FindingSeverity.HIGH,
        status=FindingStatus.VERIFIED,
        evidence_ids=[item.id for item in corroborating.evidences],
        affected_assets=[SUBJECT],
    )
    refuted_finding = Finding(
        title="Already refuted",
        description="d",
        category=FindingCategory.WPS,
        severity=FindingSeverity.HIGH,
        status=FindingStatus.REFUTED,
        affected_assets=[SUBJECT],
    )
    corroborating.findings.extend([open_finding, closed_finding, refuted_finding])

    outcomes = engine.verify_open_findings(corroborating)
    assert len(outcomes) == 1
    assert all(isinstance(item, VerificationOutcome) for item in outcomes)
    assert outcomes[0].result.status == VerificationStatus.VERIFIED


def test_verify_open_findings_respects_limit():
    engine = VerificationEngine()
    state = state_with(evidence(tool="wash", confidence=0.9, data={"wps_enabled": True}))
    for index in range(3):
        state.findings.append(
            Finding(
                title=f"finding {index}",
                description="d",
                category=FindingCategory.WPS,
                severity=FindingSeverity.MEDIUM,
                status=FindingStatus.HYPOTHESIS,
                evidence_ids=[state.evidences[0].id],
                affected_assets=[SUBJECT],
            )
        )
    assert len(engine.verify_open_findings(state, limit=2)) == 2
