"""
Tests for the audit trail: contract logging, refusals and the correlation chain.

Specification section 17 requires that a reader can answer "which operation produced this
evidence, and what did the framework conclude from it" without walking the whole event log. These
tests pin that guarantee end to end:

    assessment_id -> action_id -> execution_id -> evidence_ids -> verification_ids -> finding_ids
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from wifi_framework.contracts import (
    SCHEMA_VERSIONS,
    ActionObjective,
    ActionRequest,
    EngineId,
    EntityRef,
    EvidenceSet,
    ExecutionResult,
    ExecutionStatus,
    Observation,
    ParserRef,
    Provenance,
    TargetType,
    VerificationConclusion,
    VerificationMethod,
    VerificationResult,
    VerificationStatus,
    WorldState,
)
from wifi_framework.core.audit.logger import AuditLogger
from wifi_framework.core.models.assessment_state import AssessmentState, ExecutionRecord
from wifi_framework.core.models.evidence import ConfidenceLevel, Evidence, EvidenceType
from wifi_framework.core.models.finding import Finding, FindingCategory, FindingSeverity, FindingStatus
from wifi_framework.core.models.scope import AssessmentScope

ASSESSMENT = "66666666-6666-4666-8666-666666666666"
SUBJECT = "AA:BB:CC:DD:EE:FF"


@pytest.fixture
def logger(tmp_path: Path) -> AuditLogger:
    return AuditLogger(log_dir=str(tmp_path / "audit"), assessment_id=ASSESSMENT)


def events(logger: AuditLogger) -> list[dict]:
    path = Path(logger.log_dir) / f"{ASSESSMENT}.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def of_type(logger: AuditLogger, event_type: str) -> list[dict]:
    return [event for event in events(logger) if event["event_type"] == event_type]


def evidence_item(evidence_id: str, execution_id: str, *, bssid: str = SUBJECT) -> Evidence:
    item = Evidence.from_tool_output(
        tool_name="wash",
        capability="wps_assessment",
        evidence_type=EvidenceType.WPS,
        raw_output="raw",
        parsed_data={"bssid": bssid, "wps_enabled": True},
        parameters={"bssid": bssid},
        interface="wlan0mon",
        confidence=ConfidenceLevel.HIGH,
        execution_id=execution_id,
        raw_command="wash -i wlan0mon -s",
    )
    item.id = evidence_id
    return item


def execution_record(
    execution_id: str,
    *,
    action_id: str | None,
    evidence_ids: list[str],
    capability: str = "wps_assessment",
    tool: str = "wash",
    status: str = ExecutionStatus.SUCCESS,
) -> ExecutionRecord:
    return ExecutionRecord(
        id=execution_id,
        capability_name=capability,
        tool_binary=tool,
        interface="wlan0mon",
        exit_code=0 if status == ExecutionStatus.SUCCESS else None,
        duration_seconds=12.0,
        success=status == ExecutionStatus.SUCCESS,
        evidence_ids=list(evidence_ids),
        action_id=action_id,
        correlation_id=ASSESSMENT,
        status=status,
        artifact_ids=[f"artifact-{execution_id}"],
    )


def chain_state() -> AssessmentState:
    """A state shaped exactly as the production pipeline leaves it after a verified finding."""
    state = AssessmentState(scope=AssessmentScope(authorized_bssids=[SUBJECT]))
    state.id = ASSESSMENT
    state.evidences.extend(
        [evidence_item("evidence-1", "execution-1"), evidence_item("evidence-2", "execution-1")]
    )
    state.execution_history.append(
        execution_record("execution-1", action_id="action-1", evidence_ids=["evidence-1", "evidence-2"])
    )
    finding = Finding(
        id="finding-1",
        title="WPS enabled",
        description="WPS is enabled and may allow PIN recovery",
        category=FindingCategory.WPS,
        severity=FindingSeverity.HIGH,
        status=FindingStatus.VERIFIED,
        evidence_ids=["evidence-1", "evidence-2"],
        affected_assets=[SUBJECT],
    )
    state.findings.append(finding)
    # Written by AssessmentEngine.handle_verification_outcome in production.
    state.extra["verifications"] = [
        {
            "verification_id": "verification-1",
            "status": VerificationStatus.VERIFIED,
            "method": "multi_tool_correlation",
            "confidence": 0.96,
            "subject_id": SUBJECT,
            "hypothesis_id": "finding-1",
            "action_id": "action-1",
            "execution_id": "execution-1",
            "supporting_evidence": ["evidence-1", "evidence-2"],
            "contradicting_evidence": [],
            "independent_sources": ["wash", "airodump-ng"],
        }
    ]
    return state


# ------------------------------------------------------------- correlation chain


def test_chain_links_assessment_action_execution_evidence_verification_and_finding():
    chains = AuditLogger.correlation_chains(chain_state())
    assert len(chains) == 1
    chain = chains[0]

    assert chain["assessment_id"] == ASSESSMENT
    assert chain["action_id"] == "action-1"
    assert chain["execution_id"] == "execution-1"
    assert chain["correlation_id"] == ASSESSMENT
    assert chain["capability"] == "wps_assessment"
    assert chain["status"] == ExecutionStatus.SUCCESS
    assert sorted(chain["evidence_ids"]) == ["evidence-1", "evidence-2"]
    assert chain["verification_ids"] == ["verification-1"]
    assert chain["artifact_ids"] == ["artifact-execution-1"]
    assert chain["finding_ids"] == ["finding-1"]


def test_every_finding_is_reachable_from_some_chain():
    """M6 acceptance criterion: the chain reaches finding_ids for every finding."""
    state = chain_state()
    chains = AuditLogger.correlation_chains(state)
    linked = {finding_id for chain in chains for finding_id in chain["finding_ids"]}
    assert linked == {finding.id for finding in state.findings}


def test_evidence_ids_are_recovered_when_the_record_does_not_carry_them():
    state = chain_state()
    state.execution_history[0].evidence_ids = []
    chain = AuditLogger.correlation_chains(state)[0]
    # The evidence objects still name their execution, so the link survives.
    assert sorted(chain["evidence_ids"]) == ["evidence-1", "evidence-2"]
    assert chain["finding_ids"] == ["finding-1"]


def test_verification_is_linked_through_supporting_evidence_alone():
    """A verification recorded against evidence still reaches the chain that produced it."""
    state = chain_state()
    state.extra["verifications"][0]["execution_id"] = None
    chain = AuditLogger.correlation_chains(state)[0]
    assert chain["verification_ids"] == ["verification-1"]


def test_findings_from_other_executions_are_not_falsely_linked():
    state = chain_state()
    # A second action, its own evidence, and a finding citing only that evidence.
    state.evidences.append(evidence_item("evidence-9", "execution-9"))
    state.execution_history.append(
        execution_record("execution-9", action_id="action-9", evidence_ids=["evidence-9"])
    )
    state.findings.append(
        Finding(
            id="finding-9",
            title="Other finding",
            description="d",
            category=FindingCategory.WPS,
            severity=FindingSeverity.MEDIUM,
            status=FindingStatus.SUPPORTED,
            evidence_ids=["evidence-9"],
            affected_assets=[SUBJECT],
        )
    )

    chains = {chain["execution_id"]: chain for chain in AuditLogger.correlation_chains(state)}
    assert chains["execution-1"]["finding_ids"] == ["finding-1"]
    assert chains["execution-9"]["finding_ids"] == ["finding-9"]
    assert "finding-9" not in chains["execution-1"]["finding_ids"]


def test_unattributed_execution_is_reported_honestly_not_backfilled():
    """An execution with no action id stays traceable as unattributed rather than being guessed."""
    state = AssessmentState(scope=AssessmentScope())
    state.execution_history.append(
        execution_record("execution-x", action_id=None, evidence_ids=[], status=ExecutionStatus.UNSUPPORTED)
    )
    chain = AuditLogger.correlation_chains(state)[0]
    assert chain["action_id"] is None
    assert chain["execution_id"] == "execution-x"
    assert chain["status"] == ExecutionStatus.UNSUPPORTED
    assert chain["evidence_ids"] == []


def test_legacy_record_without_a_status_field_falls_back_to_success_flag():
    """Pre-0.4.0 records carry no contract status; the boolean still describes them honestly."""
    state = AssessmentState(scope=AssessmentScope())
    record = execution_record("execution-legacy", action_id="action-1", evidence_ids=[])
    record.status = None
    record.success = True
    state.execution_history.append(record)

    chain = AuditLogger.correlation_chains(state)[0]
    assert chain["status"] == "success"

    record.success = False
    assert AuditLogger.correlation_chains(state)[0]["status"] == "failed"


# ------------------------------------------------------------- contract catalogue


def test_catalogue_lists_every_contract_with_its_producer():
    catalogue = AuditLogger.contract_catalogue()
    assert set(catalogue) == set(SCHEMA_VERSIONS)
    assert catalogue["world-state"]["producer"] == EngineId.WORLD_MODEL.value
    assert catalogue["execution-result"]["producer"] == EngineId.EXECUTION.value
    assert catalogue["action-validation-result"]["producer"] == EngineId.POLICY.value
    assert catalogue["decision-proposal"]["producer"] == EngineId.AI.value
    assert all(entry["supported_major_versions"] == [1] for entry in catalogue.values())


# ---------------------------------------------------------------- contract trail


def test_small_contracts_are_recorded_with_their_full_payload(logger):
    request = ActionRequest(
        assessment_id=ASSESSMENT,
        action_id="action-1",
        capability="wps_assessment",
        implementation="wash",
        objective=ActionObjective.RESOLVE_INFORMATION_GAP,
        target=EntityRef(type=TargetType.ACCESS_POINT.value, id=SUBJECT),
    )
    digest = logger.log_contract(request)

    recorded = of_type(logger, "contract:action-request")[-1]["data"]
    assert recorded["payload_recorded"] is True
    assert recorded["payload"]["capability"] == "wps_assessment"
    assert recorded["payload_digest"] == digest
    assert recorded["envelope"]["schema"] == "action-request"
    assert recorded["envelope"]["version"] == "1.0"
    assert recorded["envelope"]["message_id"] == request.message_id
    assert recorded["envelope"]["correlation_id"] == request.correlation_id


def test_large_contracts_are_recorded_as_summary_plus_digest(logger):
    """world-state and evidence-set are compact: their content is already in the trail."""
    world = WorldState(
        assessment_id=ASSESSMENT,
        phase="wireless_observation",
        scope={},
        last_updated="2026-09-16T00:00:00+00:00",
    )
    logger.log_contract(world, summary={"access_points": 3})

    recorded = of_type(logger, "contract:world-state")[-1]["data"]
    assert recorded["payload_recorded"] is False
    assert "payload" not in recorded
    assert recorded["summary"] == {"access_points": 3}
    assert len(recorded["payload_digest"]) == 64


def test_compact_contract_uses_its_own_summary_when_none_is_given(logger):
    evidence_set = EvidenceSet(
        assessment_id=ASSESSMENT,
        action_id="action-1",
        execution_id="execution-1",
        parser=ParserRef(name="wash", version="1.0"),
        observations=[
            Observation(
                id="evidence-1",
                type="wps_observation",
                subject_id=SUBJECT,
                data={"wps_enabled": True},
                provenance=Provenance(execution_id="execution-1", action_id="action-1", tool="wash"),
            )
        ],
    )
    logger.log_contract(evidence_set)
    recorded = of_type(logger, "contract:evidence-set")[-1]["data"]
    assert recorded["payload_recorded"] is False
    assert recorded["summary"]["observations"] == 1


def test_full_payload_can_be_requested_explicitly(logger):
    world = WorldState(
        assessment_id=ASSESSMENT, phase="verification", scope={}, last_updated="2026-09-16T00:00:00+00:00"
    )
    logger.log_contract(world, full_payload=True)
    recorded = of_type(logger, "contract:world-state")[-1]["data"]
    assert recorded["payload_recorded"] is True
    assert recorded["payload"]["phase"] == "verification"


def test_digest_lets_a_message_be_matched_against_a_reconstructed_one(logger):
    result = ExecutionResult(
        assessment_id=ASSESSMENT,
        action_id="action-1",
        execution_id="execution-1",
        capability="wps_assessment",
        implementation="wash",
        status=ExecutionStatus.SUCCESS,
        exit_code=0,
        duration_ms=1200,
    )
    digest = logger.log_contract(result)
    assert digest == ExecutionResult.parse(result.to_message()).digest()


# --------------------------------------------------------------------- refusals


def test_refusal_is_recorded_with_stage_and_structured_reason(logger):
    logger.log_contract_rejection(
        "action-1",
        {"code": "scope_denied_wireless", "stage": "scope", "retriable": False},
        "scope",
    )
    recorded = of_type(logger, "action_rejected")[-1]["data"]
    assert recorded["action_id"] == "action-1"
    assert recorded["stage"] == "scope"
    assert recorded["reason"]["code"] == "scope_denied_wireless"
    assert recorded["reason"]["retriable"] is False


def test_verification_outcome_is_recorded(logger):
    logger.log_verification("finding-1", "multi_tool_correlation", True, "evidence-1")
    recorded = of_type(logger, "verification")[-1]["data"]
    assert recorded["finding_id"] == "finding-1"
    assert recorded["success"] is True
    assert recorded["evidence_id"] == "evidence-1"


# ------------------------------------------------------------------------ report


def test_report_carries_the_contract_trail_and_correlation_chains(logger):
    state = chain_state()
    logger.log_contract(
        VerificationResult(
            assessment_id=ASSESSMENT,
            verification_id="verification-1",
            status=VerificationStatus.VERIFIED,
            subject_id=SUBJECT,
            confidence=0.96,
            supporting_evidence=["evidence-1", "evidence-2"],
            independent_sources=["wash", "airodump-ng"],
            required_confidence=0.85,
            conclusion=VerificationConclusion(
                state=VerificationStatus.VERIFIED,
                details={"reason": "two independent sources aggregate above the threshold"},
            ),
            method=VerificationMethod.MULTI_TOOL_CORRELATION,
        )
    )
    report = logger.generate_report(state)

    assert report["assessment_id"] == state.id
    assert report["contracts"] == AuditLogger.contract_catalogue()
    assert report["correlation_chains"][0]["finding_ids"] == ["finding-1"]
    assert report["audit_events_count"] == len(events(logger))
    assert report["finding_traces"]


def test_report_is_json_serialisable_and_saveable(logger, tmp_path):
    state = chain_state()
    path = logger.save_report(state, output_path=str(tmp_path / "report.json"))
    loaded = json.loads(Path(path).read_text())
    assert loaded["correlation_chains"][0]["execution_id"] == "execution-1"


def test_audit_log_is_append_only_jsonl(logger):
    logger.log_contract(
        ActionRequest(
            assessment_id=ASSESSMENT,
            action_id="action-1",
            capability="wps_assessment",
            implementation="wash",
        )
    )
    logger.log_contract_rejection("action-2", {"code": "unknown_capability"}, "capability")

    path = Path(logger.log_dir) / f"{ASSESSMENT}.jsonl"
    lines = [line for line in path.read_text().splitlines() if line.strip()]
    assert len(lines) == len(events(logger))
    assert all({"event_type", "timestamp", "data"} <= set(json.loads(line)) for line in lines)
